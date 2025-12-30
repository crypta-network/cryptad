package network.crypta.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import network.crypta.client.FECCodec;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.USKManager;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.io.xfer.AbortedException;
import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.pluginmanager.PluginRespirator;
import network.crypta.pluginmanager.PluginStores;
import network.crypta.store.KeyCollisionException;
import network.crypta.support.Base64;
import network.crypta.support.HTMLNode;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.StringArrCallback;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates the client-facing services layered on top of a {@link Node}.
 *
 * <p>{@code NodeClientCore} wires persistence, request scheduling, USK management, client
 * endpoints, and temporary storage so higher-level APIs can operate against a single, consistent
 * context. It builds and exposes a {@link ClientContext}, configures bucket factories for in-memory
 * and on-disk use, and integrates with {@link NodeStats} to report per-request costs. Startup is
 * multiphase: construction performs registration and wiring, while {@link #start()} activates
 * background services and resumes persisted requests on a separate executor task. Most entry points
 * run on node executor threads; accessors that expose mutable configuration state are synchronized
 * to provide a stable snapshot.
 *
 * <ul>
 *   <li>Provide client-layer factories and shared services for request handlers.
 *   <li>Gate disk usage and security policy for downloads and uploads.
 *   <li>Bridge persistence and throttling with node lifecycle events.
 * </ul>
 *
 * @see Node
 * @see ClientContext
 * @see ClientEndpoints
 * @see RequestStarterGroup
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

  /** Manages USK state. Access via {@link #getUskManager()}. */
  private final USKManager uskManager;

  /** Request starter group. Access via {@link #getRequestStarters()}. */
  private final RequestStarterGroup requestStarters;

  /**
   * Runs memory-bounded background jobs such as FEC decoding within configured capacity and thread
   * limits. The runner is shared by client operations, so callers should treat it as a long-lived
   * service and avoid shutting it down directly; lifecycle is owned by the core.
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

  final File downloadsDir;
  private File[] downloadAllowedDirs;
  private boolean includeDownloadDir;
  private boolean downloadAllowedEverywhere;
  private boolean downloadDisabled;
  private File[] uploadAllowedDirs;
  private boolean uploadAllowedEverywhere;

  /** Temp bucket factory. Access via {@link #getTempBucketFactory()}. */
  private final TempBucketFactory tempBucketFactory;

  /** Persistent temp bucket factory. Access via {@link #getPersistentTempBucketFactory()}. */
  private final PersistentTempBucketFactory persistentTempBucketFactory;

  /** Persistence wiring for throttles, FCP root, and disk checks. */
  private final NodeClientPersistence persistence;

  /** Persists and reloads client-layer state such as throttles and pending requests. */
  private final ClientLayerPersister clientLayerPersister;

  /** Back-reference to the owning {@link Node}. Access via {@link #getNode()}. */
  private final Node node;

  /** Random source for request IDs and other non-cryptographic needs. */
  private final RandomSource random;

  final File tempDir; // Temporary buckets (non-persistent)
  final File persistentTempDir;

  /** User alert manager. Access via {@link #getAlerts()}. */
  private final UserAlertManager alerts;

  /** Client-facing endpoints (TMCI, FCP, and FProxy wiring). */
  private final ClientEndpoints endpoints;

  /**
   * Compressor used for network transfers and stored blocks.
   *
   * <p>The instance is created during construction and is shared across requests. Callers should
   * treat it as a core-owned component and avoid reconfiguring it outside managed setup.
   */
  public final RealCompressor compressor;

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
  private boolean alwaysCommit;
  private final PluginStores pluginStores;
  private boolean lazyStartDatastoreChecker;

  private boolean finishedInitStorage;
  private boolean finishingInitStorage;

  NodeClientCore(
      Node node,
      NodeClientCoreInit init,
      int portNumber,
      int sortOrder,
      DatabaseKey databaseKey,
      MasterSecret persistentSecret)
      throws NodeInitException {
    this.node = node;
    this.random = node.getRandom();
    this.pluginStores = new PluginStores(node, init.installConfig());

    sortOrder = registerLazyStartDatastoreChecker(init, sortOrder);

    storeChecker =
        new DatastoreChecker(
            node, lazyStartDatastoreChecker, node.getExecutor(), "Datastore checker");
    byte[] pwdBuf = new byte[16];
    random.nextBytes(pwdBuf);
    compressor = new RealCompressor();
    this.formPassword = Base64.encode(pwdBuf);
    alerts = new UserAlertManager(this);
    persistence = new NodeClientPersistence(this, init.nodeConfig(), node, sortOrder);
    sortOrder = persistence.getSortOrderAfter();

    SimpleFieldSet throttleFS = persistence.readThrottle();
    if (LOG.isDebugEnabled()) LOG.debug("Read throttleFS:\n{}", throttleFS);

    if (LOG.isDebugEnabled()) LOG.debug("Serializing RequestStarterGroup from:\n{}", throttleFS);

    // Temp files

    // Adaptive default: cacheDir/tmp
    File defaultCacheDir = NodeClientCoreSupport.resolveDefaultCacheDir();
    File defaultDataDir = NodeClientCoreSupport.resolveDefaultDataDir();

    this.tempDir =
        NodeClientCoreSupport.setupProgramDirFile(
            node,
            init.installConfig(),
            "tempDir",
            new File(defaultCacheDir, "tmp").getPath(),
            "NodeClientCore.tempDir",
            "NodeClientCore.tempDirLong");

    // Note: remove back compatibility hack when safe.
    deleteLegacyTempDirIfPresent(node);

    FileUtil.setOwnerRWX(getTempDir());

    // Temp filename generator for ephemeral bucket file names.
    FilenameGenerator tempFilenameGenerator = createTempFilenameGeneratorOrThrow();

    uskManager = new USKManager(this);

    // Persistent temp files
    sortOrder = registerEncryptPersistentTempBuckets(init, sortOrder);

    this.persistentTempDir =
        NodeClientCoreSupport.setupProgramDirFile(
            node,
            init.installConfig(),
            "persistentTempDir",
            new File(defaultCacheDir, "persistent-temp").getPath(),
            "NodeClientCore.persistentTempDir",
            "NodeClientCore.persistentTempDirLong");

    PersistentTempBucketFactory ptbf = createPersistentTempBucketFactory(init);
    this.persistentTempBucketFactory = ptbf;
    // Persistent filename generator for restart-safe bucket file names.
    FilenameGenerator persistentFilenameGenerator = ptbf.fg;

    // Remove legacy persistent-blob file to reclaim space for migration.
    deleteOldPersistentBlobIfPresent();

    // Allocate ~10% of available memory to the RAM bucket pool by default.
    int defaultRamBucketPoolSize = computeDefaultRamBucketPoolSize(NodeStarter.getMemoryLimitMB());

    // Max bucket size is 5% of the pool, minimum 32 KiB (one block; typical case).
    long maxBucketSize = Math.max(32768, (defaultRamBucketPoolSize * 1024 * 1024) / 20);

    sortOrder = registerMaxRamBucketSize(init, sortOrder, maxBucketSize);

    sortOrder = registerRamBucketPoolSize(init, sortOrder, defaultRamBucketPoolSize);

    sortOrder = registerEncryptTempBuckets(init, sortOrder);

    initDiskSpaceLimits(init, sortOrder);

    MasterSecret cryptoSecretTransient = new MasterSecret();
    tempBucketFactory =
        new TempBucketFactory(
            node.getExecutor(),
            tempFilenameGenerator,
            init.nodeConfig().getLong("maxRAMBucketSize"),
            init.nodeConfig().getLong("RAMBucketPoolSize"),
            init.nodeConfig().getBoolean("encryptTempBuckets"),
            minDiskFreeShortTerm,
            cryptoSecretTransient);

    clientLayerPersister =
        new ClientLayerPersister(
            node.getExecutor(),
            node.getTicker(),
            node,
            this,
            persistentTempBucketFactory,
            tempBucketFactory);

    SemiOrderedShutdownHook shutdownHook = SemiOrderedShutdownHook.get();
    installCoreShutdownHooks(shutdownHook);

    ClientContextResources clientContextResources =
        NodeClientCoreSupport.createClientContextResources(
            node,
            tempBucketFactory,
            MAX_ARCHIVE_HANDLERS,
            MAX_CACHED_ARCHIVE_DATA,
            MAX_ARCHIVED_FILE_SIZE,
            MAX_CACHED_ELEMENTS,
            MAX_RUNNING_HEALING_INSERTS);

    persistence.initDiskChecker(
        persistentFilenameGenerator,
        persistentTempDir,
        minDiskFreeLongTerm,
        tempBucketFactory,
        init.nodeConfig().getBoolean(CFG_ENCRYPT_PERSISTENT_TEMP_BUCKETS));
    persistence.installDiskChecker(persistentTempBucketFactory);
    HighLevelSimpleClient client = makeClient((short) 0, false, false);
    FetchContext defaultFetchContext = client.getFetchContext();
    InsertContext defaultInsertContext = client.getInsertContext(false);
    int maxMemoryLimitedJobThreads = computeMaxMemoryLimitedJobThreads();
    sortOrder = registerMemoryLimitedJobThreadLimit(init, sortOrder, maxMemoryLimitedJobThreads);
    long overallMemoryLimit = NodeStarter.getMemoryLimitBytes();
    long defaultMemoryLimitedJobMemoryLimit =
        computeDefaultMemoryLimitedJobMemoryLimit(overallMemoryLimit);
    sortOrder =
        registerMemoryLimitedJobMemoryLimit(init, sortOrder, defaultMemoryLimitedJobMemoryLimit);
    memoryLimitedJobRunner =
        new MemoryLimitedJobRunner(
            init.nodeConfig().getLong("memoryLimitedJobMemoryLimit"),
            init.nodeConfig().getInt("memoryLimitedJobThreadLimit"),
            node.getExecutor(),
            RequestStarter.NUMBER_OF_PRIORITY_CLASSES);
    installFecShutdownHooks(shutdownHook);
    clientContext =
        persistence.createClientContext(
            node,
            clientLayerPersister,
            node.getExecutor(),
            clientContextResources,
            persistentTempBucketFactory,
            tempBucketFactory,
            uskManager,
            random,
            node.getFastWeakRandom(),
            node.getTicker(),
            memoryLimitedJobRunner,
            tempFilenameGenerator,
            persistentFilenameGenerator,
            tempBucketFactory,
            persistence.getPersistentRafFactory(),
            tempBucketFactory.getUnderlyingRAFFactory(),
            compressor,
            storeChecker,
            cryptoSecretTransient,
            init,
            defaultFetchContext,
            defaultInsertContext);
    compressor.setClientContext(getClientContext());
    storeChecker.setContext(getClientContext());
    getClientLayerPersister().start(getClientContext());

    requestStarters = createRequestStarters(node, portNumber, init, throttleFS);

    clientContext.init(requestStarters, alerts);

    setupSecretAndInitStorage(databaseKey, persistentSecret);

    installPhysicalThreatLevelListener();

    // Downloads directory

    this.downloadsDir =
        NodeClientCoreSupport.setupProgramDirFile(
            node,
            init.nodeConfig(),
            "downloadsDir",
            new File(defaultDataDir, DOWNLOADS_DIR_NAME).getPath(),
            "NodeClientCore.downloadsDir",
            "NodeClientCore.downloadsDirLong",
            l10n("couldNotFindOrCreateDir"));

    // Downloads allowed, uploads allowed

    sortOrder = registerDownloadAllowedDirs(init, sortOrder);

    sortOrder = registerUploadAllowedDirs(init, sortOrder);

    LOG.info("Initializing USK Manager");
    uskManager.init(getClientContext());

    sortOrder = registerMaxBackgroundUSKFetchers(init, sortOrder);

    // This is all part of construction, not of start().
    // Some plugins depend on it, so it needs to be *created* before they are started.

    // TMCI and FCP (including persistent requests so needs to start before FProxy)
    ClientEndpoints.InitResult endpointsInit =
        ClientEndpoints.create(node, this, init, persistence, clientContext);
    endpoints = endpointsInit.endpoints();
    TextModeClientInterface directTMCI = endpointsInit.directTMCI();
    if (directTMCI != null) {
      endpoints.setDirectTMCI(directTMCI);
      node.getExecutor().execute(directTMCI, "Direct text mode interface");
    }

    // FProxy
    // Note: This wiring is a stopgap; plugins should handle this in the future.
    endpoints.registerStartupAlerts(
        alerts, this, l10n("startingUpTitle"), l10n("startingUp"), l10n("startingUpShort"));
    endpoints.configureBucketFactory(tempBucketFactory);

    registerAlwaysCommit(init, sortOrder);
    alwaysCommit = init.nodeConfig().getBoolean("alwaysCommit");
    NodeClientCoreSupport.registerStorageAlerts(alerts, this);
  }

  /**
   * Recomputes the minimum free-disk threshold for the persistent RAF factory.
   *
   * <p>The calculation adds the current RAM-backed temp bucket allowance to the configured
   * long-term free-space requirement so the persistent RAF factory can accommodate a migration of
   * temporary data to disk. It updates the persisted factory only when one is present and uses the
   * current in-memory configuration snapshot to compute the threshold.
   */
  protected void updatePersistentRAFSpaceLimit() {
    // The temp bucket factory may have to migrate everything to disk.
    // So we add the RAM limit for the temp factory to the disk limit for the persistent one.
    if (persistence.hasPersistentRafFactory()) {
      long size;
      synchronized (this) {
        size = minDiskFreeLongTerm;
      }
      size += tempBucketFactory.getMaxRamUsed();
      persistence.updateMinDiskSpace(size);
    }
  }

  private void initDiskSpaceLimits(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
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
                  if (val < 0)
                    throw new InvalidConfigValueException(l10n("minDiskFreeMustBePositive"));
                  minDiskFreeLongTerm = val;
                }
                updatePersistentRAFSpaceLimit();
              }
            },
            true);
    minDiskFreeLongTerm = init.nodeConfig().getLong("minDiskFreeLongTerm");

    init.nodeConfig()
        .register(
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
                  if (val < 0)
                    throw new InvalidConfigValueException(l10n("minDiskFreeMustBePositive"));
                  minDiskFreeShortTerm = val;
                }
                tempBucketFactory.setMinDiskSpace(val);
              }
            },
            true);
    minDiskFreeShortTerm = init.nodeConfig().getLong("minDiskFreeShortTerm");
    // Do not register the UserAlert yet, since we haven't finished constructing stuff it uses.
  }

  boolean lateInitDatabase(DatabaseKey databaseKey) {
    LOG.info("Late database initialisation: starting middle phase");
    if (initStorage(databaseKey)) {
      // Don't actually start the database thread yet, messy concurrency issues.
      endpoints.loadPersistentRequestsIfNeeded();
      LOG.info("Late database initialisation completed.");
      return true;
    }
    LOG.warn(
        "Late database initialisation failed: wrong master key/password provided (hasKey={}).",
        databaseKey != null);
    return false;
  }

  /**
   * Give ClientLayerPersister a filename and possibly an encryption key. May cause it to load, but
   * can also be called afterward to change where to write to.
   *
   * @param databaseKey The encryption key.
   * @return {@code true} if storage was initialized; {@code false} if the key was missing or
   *     invalid.
   */
  private boolean initStorage(DatabaseKey databaseKey) {
    try {
      getClientLayerPersister()
          .setFilesAndLoad(
              node.getNodeDir(),
              "client.dat",
              node.wantEncryptedDatabase(),
              node.wantNoPersistentDatabase(),
              databaseKey,
              requestStarters);
      return true;
    } catch (MasterKeysWrongPasswordException _) {
      return false;
    }
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
    (isSSK
            ? node.getNodeStats().localSskFetchBytesSentAverage
            : node.getNodeStats().localChkFetchBytesSentAverage)
        .report(rs.getTotalSentBytes());
    (isSSK
            ? node.getNodeStats().localSskFetchBytesReceivedAverage
            : node.getNodeStats().localChkFetchBytesReceivedAverage)
        .report(rs.getTotalReceivedBytes());
    if (status == RequestSender.SUCCESS)
      (isSSK
              ? node.getNodeStats().successfulSskFetchBytesReceivedAverage
              : node.getNodeStats().successfulChkFetchBytesReceivedAverage)
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

  private PersistentTempBucketFactory createPersistentTempBucketFactory(NodeClientCoreInit init)
      throws NodeInitException {
    try {
      return new PersistentTempBucketFactory(
          persistentTempDir,
          "freenet-temp-",
          node.getFastWeakRandom(),
          init.nodeConfig().getBoolean(CFG_ENCRYPT_PERSISTENT_TEMP_BUCKETS));
    } catch (IOException e) {
      String msg = "Could not find or create persistent temporary directory: " + e;
      LOG.error(msg, e);
      throw new NodeInitException(NodeInitException.EXIT_BAD_DIR, msg);
    }
  }

  private void deleteOldPersistentBlobIfPresent() {
    File oldBlobFile = new File(persistentTempDir, "persistent-blob.tmp");
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
          NodeClientCoreSupport.deleteFile(oldBlobFile);
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
      Node node, int portNumber, NodeClientCoreInit init, SimpleFieldSet throttleFS)
      throws NodeInitException {
    try {
      return new RequestStarterGroup(
          node, this, portNumber, random, init.config(), throttleFS, clientContext);
    } catch (InvalidConfigValueException e1) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_CONFIG, e1.toString());
    }
  }

  private void setupSecretAndInitStorage(DatabaseKey databaseKey, MasterSecret persistentSecret) {
    if (persistentSecret != null) {
      setupMasterSecret(persistentSecret);
    }
    if (initStorage(databaseKey)) {
      return;
    }
    LOG.warn("Cannot load persistent requests, awaiting password ...");
    node.setDatabaseAwaitingPassword();
  }

  private void installPhysicalThreatLevelListener() {
    node.getSecurityLevels()
        .addPhysicalThreatLevelListener((_, newLevel) -> onPhysicalThreatLevelChanged(newLevel));
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
    persistence.setPersistentRafEncryption(enable);
  }

  private void maybeReloadStorageAfterThreatChange() {
    if (!getClientLayerPersister().hasLoaded()) return;
    // May need to change filenames for client.dat* or even create them.
    if (initStorage(NodeClientCore.this.getNode().getDatabaseKey())) {
      return;
    }
    NodeClientCore.this.getNode().setDatabaseAwaitingPassword();
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

  private static int registerMaxBackgroundUSKFetchers(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
            "maxBackgroundUSKFetchers",
            64,
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
                  throw new InvalidConfigValueException(
                      l10n("maxUSKFetchersMustBeGreaterThanZero"));
                maxBackgroundUSKFetchers = uskFetch;
              }
            },
            false);
    maxBackgroundUSKFetchers = init.nodeConfig().getInt("maxBackgroundUSKFetchers");
    return sortOrder + 1;
  }

  private int registerDownloadAllowedDirs(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
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
                  String[] dirs =
                      new String[downloadAllowedDirs.length + (includeDownloadDir ? 1 : 0)];
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
    setDownloadAllowedDirs(init.nodeConfig().getStringArr("downloadAllowedDirs"));
    return sortOrder + 1;
  }

  private int registerUploadAllowedDirs(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
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
    setUploadAllowedDirs(init.nodeConfig().getStringArr("uploadAllowedDirs"));
    return sortOrder + 1;
  }

  private int registerMemoryLimitedJobThreadLimit(
      NodeClientCoreInit init, int sortOrder, int maxMemoryLimitedJobThreads) {
    init.nodeConfig()
        .register(
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
                  throw new InvalidConfigValueException(
                      l10n("memoryLimitedJobThreadLimitMustBe1Plus"));
                memoryLimitedJobRunner.setMaxThreads(val);
              }
            },
            false);
    return sortOrder + 1;
  }

  private int registerMemoryLimitedJobMemoryLimit(
      NodeClientCoreInit init, int sortOrder, long defaultMemoryLimitedJobMemoryLimit) {
    init.nodeConfig()
        .register(
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
  private int registerAlwaysCommit(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
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

  private int registerMaxRamBucketSize(NodeClientCoreInit init, int sortOrder, long maxBucketSize) {
    init.nodeConfig()
        .register(
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
      NodeClientCoreInit init, int sortOrder, int defaultRamBucketPoolSize) {
    init.nodeConfig()
        .register(
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

  private int registerEncryptTempBuckets(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
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

  private int registerEncryptPersistentTempBuckets(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
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
                persistence.setPersistentRafEncryption(val);
              }
            });
    return sortOrder + 1;
  }

  private void deleteLegacyTempDirIfPresent(Node node) {
    File oldTemp = node.runDir().file("temp-" + node.getDarknetPortNumber());
    if (oldTemp.exists() && oldTemp.isDirectory() && !FileUtil.equals(tempDir, oldTemp)) {
      LOG.info("Deleting old temporary dir: {}", oldTemp);
      try {
        FileUtil.secureDeleteAll(oldTemp);
      } catch (IOException _) {
        // Ignore.
      }
    }
  }

  private int registerLazyStartDatastoreChecker(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
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
    lazyStartDatastoreChecker = init.nodeConfig().getBoolean("lazyStartDatastoreChecker");
    return sortOrder + 1;
  }

  /**
   * Returns whether downloads are globally disabled by configuration.
   *
   * <p>This flag is derived from the current allowlist configuration. When disabled, directory
   * checks are short-circuited and no target is considered eligible, even if it matches an
   * allowlisted path. The value is a snapshot and can change when configuration is updated at
   * runtime.
   *
   * @return {@code true} if downloads are disabled and all targets are rejected.
   */
  public boolean isDownloadDisabled() {
    return downloadDisabled;
  }

  /**
   * Configures directories where downloads may be written.
   *
   * <p>Recognized entries include {@code "all"} to allow any destination and {@code "downloads"} to
   * allow the configured downloads directory. Any other string is treated as a filesystem path and
   * stored as a {@link File}. Passing an empty array disables downloads entirely. The configuration
   * is applied immediately and affects subsequent permission checks.
   *
   * @param val allowlist entries describing special tokens or absolute/relative paths.
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
   * <p>Recognized entries include {@code "all"} to allow any source. Any other string is treated as
   * a filesystem path and stored as a {@link File}. The configuration is applied immediately and
   * affects subsequent permission checks for upload sources. The method performs no I/O and updates
   * in-memory policy.
   *
   * @param val allowlist entries describing special tokens or filesystem paths.
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
   * <p>This method activates request starters, the datastore checker, client endpoints, and
   * plugins, then schedules a low-priority completion task to migrate persistent temporary buckets
   * and resume pending requests. Call it during node startup after construction has finished
   * wiring. Exceptions during migration are logged and do not prevent the remaining services from
   * running.
   */
  public void start() {

    persistence.startThrottle();

    requestStarters.start();

    storeChecker.start();
    endpoints.maybeStart();
    node.getPluginManager().start();
    node.getIpDetector().ipDetectorManager.start();

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
                endpoints.unregisterStartupAlert(alerts);
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
   * <p>If the data is found locally the listener is notified and no network request is started.
   * Otherwise, a request sender is created and the listener receives completion or failure
   * callbacks; some successful outcomes may be delivered via the pending-keys mechanism instead of
   * the listener. The call is non-blocking and returns after scheduling work using a freshly
   * generated UID. Store access is controlled by {@code localOnly} and {@code ignoreStore}; when
   * both are {@code false} the datastore is checked first and routing proceeds on miss.
   *
   * @param key key to fetch; typically a {@code CHK} or {@link NodeSSK}.
   * @param offersOnly when true, fetch only from offered-key sources.
   * @param listener callback notified on completion or failure of the request.
   * @param canReadClientCache whether this request may read from the client cache.
   * @param canWriteClientCache whether this request may write into the client cache.
   * @param realTimeFlag true for latency-optimized routing; false for bulk throughput.
   * @param localOnly true to check only local store and skip routing.
   * @param ignoreStore true to bypass datastore and always create a request.
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
    if (!node.getTracker().lockUID(uid, isSSK, false, false, true, realTimeFlag, tag)) {
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
    startAsyncGet(
        key,
        offersOnly,
        uid,
        listener,
        tag,
        canReadClientCache,
        canWriteClientCache,
        htl,
        realTimeFlag,
        localOnly,
        ignoreStore,
        isSSK,
        startTime);
  }

  /**
   * Start an asynchronous fetch of the key in question, which will complete to the datastore. It
   * will not decode the data because we don't provide a ClientKey. It will not return anything and
   * will run asynchronously. Caller is responsible for unlocking the UID.
   *
   * @param key The key being fetched.
   * @param offersOnly If true, only fetch the key from nodes that have offered it, using
   *     GetOfferedKeys, don't do a normal fetch for it.
   * @param uid The UID of the request. This should already be locked before calling.
   * @param requestTag The RequestTag for the request; used for request lifecycle callbacks.
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
   * @param isSSK Whether the request targets an SSK key type.
   * @param startTime Start time in milliseconds since epoch for metrics.
   */
  @SuppressWarnings("java:S1181")
  private void startAsyncGet(
      Key key,
      boolean offersOnly,
      long uid,
      RequestCompletionListener listener,
      Object requestTag,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      short htl,
      boolean realTimeFlag,
      boolean localOnly,
      boolean ignoreStore,
      boolean isSSK,
      long startTime) {
    RequestTag tag = (RequestTag) requestTag;
    RequestSenderListener senderListener =
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
           * @param rs The sender that completed and reported the status.
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
        };
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
        senderListener.onDataFoundLocally();
        return; // Already have it.
      }
      if (o == null) {
        senderListener.onNotStarted(false);
        tag.unlockHandler();
        return;
      }
      RequestSender rs = (RequestSender) o;
      rs.addListener(senderListener);
      if (rs.uid != uid) tag.unlockHandler();
      // Else it has started a request.
      if (LOG.isDebugEnabled()) LOG.debug("Started {} for {} for {}", o, uid, key);
    } catch (RuntimeException | Error e) {
      LOG.error("Caught error trying to start request: {}", e, e);
      senderListener.onNotStarted(true);
    }
  }

  /**
   * Synchronously fetches a block for a client key.
   *
   * <p>This method blocks until the fetch completes or fails. Depending on {@code localOnly} and
   * {@code ignoreStore}, it may read from the datastore or issue a routed request through the
   * network. It returns a verified client block on success and throws a {@link
   * LowLevelGetException} on any failure. The request uses an internally generated UID and releases
   * tracking resources before returning.
   *
   * @param key client key to fetch; must be {@link ClientCHK} or {@link ClientSSK}.
   * @param localOnly true to consult only the datastore and stop on miss.
   * @param ignoreStore true to bypass datastore and route immediately.
   * @param canWriteClientCache whether the request may write to the client cache.
   * @param realTimeFlag true for latency-optimized routing; false for bulk routing.
   * @return verified client block, owned by the caller for use.
   * @throws LowLevelGetException when not found, verify fails, or internal errors occur.
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
   * @return the verified client block.
   * @throws LowLevelGetException if the data is not found, recently failed, transfer fails, verify
   *     fails, or on internal error.
   */
  ClientKeyBlock realGetCHK(
      ClientCHK key,
      boolean localOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean realTimeFlag)
      throws LowLevelGetException {
    long startTime = System.currentTimeMillis();
    long uid = makeUID();
    RequestTag tag = new RequestTag(false, RequestTag.START.LOCAL, null, realTimeFlag, uid, node);
    if (!node.getTracker().lockUID(uid, false, false, false, true, realTimeFlag, tag)) {
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
          return NodeClientCoreSupport.buildClientChkBlock(block, key);
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

  private ClientKeyBlock processChkRequestLoop(
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

      ClientKeyBlock maybe = tryReturnChkBlock(rs, key, status);
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

  private ClientKeyBlock tryReturnChkBlock(RequestSender rs, ClientCHK key, int status)
      throws LowLevelGetException {
    if (status == RequestSender.SUCCESS)
      try {
        return NodeClientCoreSupport.buildClientChkBlock(
            rs.getPRB().getBlock(), rs.getHeaders(), key);
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

  ClientKeyBlock realGetSSK(
      ClientSSK key,
      boolean localOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean realTimeFlag)
      throws LowLevelGetException {
    long startTime = System.currentTimeMillis();
    long uid = makeUID();
    RequestTag tag = new RequestTag(true, RequestTag.START.LOCAL, null, realTimeFlag, uid, node);
    if (!node.getTracker().lockUID(uid, true, false, false, true, realTimeFlag, tag)) {
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
          return NodeClientCoreSupport.buildClientSskBlock(block, key);
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

  private ClientKeyBlock processSskRequestLoop(
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
          return NodeClientCoreSupport.buildClientSskBlock(block, key);
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
   * <p>This entry point accepts either CHK or SSK blocks and dispatches to the appropriate insert
   * path. It performs local bookkeeping, records costs, and may store the block locally according
   * to caching rules. The call blocks until the insert completes or fails. Failures are mapped to
   * {@link LowLevelPutException} codes describing routing, overload, or collision outcomes.
   *
   * @param block block to insert; must be a {@link CHKBlock} or {@link SSKBlock}.
   * @param canWriteClientCache whether the insert may update the client cache.
   * @param forkOnCacheable whether to fork when the block is cacheable.
   * @param preferInsert whether to prefer insert when multiple strategies apply.
   * @param ignoreLowBackoff whether to ignore low backoff during routing.
   * @param realTimeFlag true for latency-optimized inserts; false for bulk routing.
   * @throws LowLevelPutException when routing fails, overload occurs, or an internal error arises.
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

  /**
   * Inserts a CHK block into the network and optionally caches it locally.
   *
   * <p>This variant constructs a CHK insert sender, waits for completion, reports costs, and stores
   * the block according to cache policy. It blocks until the insert completes and throws a {@link
   * LowLevelPutException} on routing failure, overload, or internal errors. The method generates
   * and locks a request UID internally and releases it before returning.
   *
   * @param block CHK block to insert and potentially store locally.
   * @param canWriteClientCache whether the insert may update the client cache.
   * @param forkOnCacheable whether to fork when the block is cacheable.
   * @param preferInsert whether to prefer insert when multiple strategies apply.
   * @param ignoreLowBackoff whether to ignore low backoff during routing.
   * @param realTimeFlag true for latency-optimized inserts; false for bulk routing.
   * @throws LowLevelPutException when routing fails, overload occurs, or internal errors arise.
   */
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
    if (!node.getTracker().lockUID(uid, false, true, false, true, realTimeFlag, tag)) {
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
      node.getNodeStats().localChkInsertBytesSentAverage.report(sent);
      node.getNodeStats().localChkInsertBytesReceivedAverage.report(received);
      if (status == CHKInsertSender.SUCCESS)
        node.getNodeStats().successfulChkInsertBytesSentAverage.report(sent);
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
   * <p>This method performs a local collision check using the client cache, then starts an SSK
   * insert sender and waits for completion. It reports costs, stores the block when appropriate,
   * and throws {@link LowLevelPutException} for collisions, routing failures, overload, or internal
   * errors. The call blocks until the insert completes and always releases the request UID.
   *
   * @param block SSK block to insert and potentially store locally.
   * @param canWriteClientCache whether the insert may update the client cache.
   * @param forkOnCacheable whether to fork when the block is cacheable.
   * @param preferInsert whether to prefer insert when multiple strategies apply.
   * @param ignoreLowBackoff whether to ignore low backoff during routing.
   * @param realTimeFlag true for latency-optimized inserts; false for bulk routing.
   * @throws LowLevelPutException on collision, routing failure, overload, or internal error.
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
    if (!node.getTracker().lockUID(uid, true, true, false, true, realTimeFlag, tag)) {
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
      node.getNodeStats().localSskInsertBytesSentAverage.report(sent);
      node.getNodeStats().localSskInsertBytesReceivedAverage.report(received);
      if (status == SSKInsertSender.SUCCESS)
        node.getNodeStats().successfulSskInsertBytesSentAverage.report(sent);
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
   * <p>The returned client shares this core's {@link ClientContext}, bucket factories, and random
   * source so its requests are scheduled and accounted for with the node. The client respects the
   * provided priority class and real-time flag, which influence routing and throttling behavior.
   * This method does not start network activity by itself; it only constructs a configured client
   * instance.
   *
   * @param prioClass priority class assigned to requests from the client.
   * @param forceDontIgnoreTooManyPathComponents whether to disable path-component pruning for
   *     overly long paths.
   * @param realTimeFlag true for latency-optimized requests; false for bulk requests.
   * @return configured {@link HighLevelSimpleClient} bound to this core and context.
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

  /**
   * Returns client endpoints (FCP, TMCI, and HTTP toadlet container).
   *
   * <p>The returned {@link ClientEndpoints} instance owns the lifecycle of the FCP and TMCI servers
   * and the HTTP toadlet container for this node. It is created during construction and remains
   * shared across the node lifecycle. Callers should treat it as core-owned and avoid stopping
   * endpoints outside managed shutdown paths.
   *
   * @return the shared {@link ClientEndpoints} instance for this node.
   */
  public ClientEndpoints getEndpoints() {
    return endpoints;
  }

  /**
   * Returns the configured downloads directory.
   *
   * <p>The directory is resolved during initialization and represents the default location used
   * when downloads are permitted. The returned {@link File} is the internal instance used by the
   * core, so callers should treat it as shared and avoid mutating configuration through it.
   *
   * @return configured downloads directory {@link File} used by permission checks.
   */
  public File getDownloadsDir() {
    return downloadsDir;
  }

  /**
   * Queues a low-priority reinsert of a key block.
   *
   * <p>The block is wrapped in a {@link SimpleSendableInsert} and scheduled on the request starters
   * at the maximum priority class for reinserts. The operation is asynchronous; it enqueues work
   * and returns immediately without waiting for completion. Use it to refresh availability for
   * already known data.
   *
   * @param block key block to reinsert and schedule for background routing.
   */
  public void queueRandomReinsert(KeyBlock block) {
    SimpleSendableInsert ssi =
        new SimpleSendableInsert(this, block, RequestStarter.MAXIMUM_PRIORITY_CLASS);
    if (LOG.isDebugEnabled()) LOG.debug("Queueing random reinsert for {} : {}", block, ssi);
    ssi.schedule();
  }

  /**
   * Persists the current configuration to disk.
   *
   * <p>This triggers the node configuration store to write its current values to the configured
   * storage location. The operation invokes the write immediately, but the underlying storage
   * subsystem controls any buffering or durability semantics. Call it after changing configuration
   * values that must survive restart.
   */
  public void storeConfig() {
    LOG.info("Trying to write config to disk");
    node.getConfig().store();
  }

  /**
   * Returns whether the node runs in testnet mode.
   *
   * <p>This is a global setting that affects network compatibility and routing behavior. The value
   * is determined by node configuration and is not modified by this method. Use it to gate features
   * that should only operate on a test network. The accessor performs no I/O and does not modify
   * state.
   *
   * @return {@code true} if the node is configured for testnet operation.
   */
  @SuppressWarnings("unused")
  public boolean isTestnetEnabled() {
    return Node.isTestnetEnabled();
  }

  /**
   * Returns whether advanced-mode UI features are enabled in FProxy.
   *
   * <p>This flag is provided by the client endpoints configuration and controls whether advanced UI
   * features are exposed in the HTTP interface. It reflects the current configuration snapshot and
   * may change at runtime if settings are updated. The accessor performs no I/O and simply returns
   * the current flag.
   *
   * @return {@code true} if advanced-mode UI features are enabled in FProxy.
   */
  public boolean isAdvancedModeEnabled() {
    return endpoints.isAdvancedModeEnabled();
  }

  /**
   * Returns whether JavaScript is enabled in FProxy.
   *
   * <p>This flag reflects HTTP UI configuration and indicates whether the toadlet container should
   * render pages that depend on client-side scripting. It is a snapshot of current settings and may
   * change at runtime when configuration is updated. The accessor performs no I/O and simply
   * returns the current flag.
   *
   * @return {@code true} if JavaScript is enabled for the HTTP UI.
   */
  public boolean isFProxyJavascriptEnabled() {
    return endpoints.isFProxyJavascriptEnabled();
  }

  /**
   * Returns the node's user-visible name.
   *
   * <p>The name is managed by the {@link Node} configuration and can be displayed in UI surfaces or
   * status messages. The value is a snapshot and may be empty if the user has not configured a
   * custom name. The accessor performs no I/O and returns the current in-memory value.
   *
   * @return current user-visible node name, which may be empty.
   */
  public String getMyName() {
    return node.getMyName();
  }

  /**
   * Returns the configured maximum number of background USK fetchers.
   *
   * <p>This limit is loaded from configuration and is used by USK scheduling to cap concurrent
   * background fetch activity. The value is a snapshot and can change if configuration is updated
   * at runtime. Callers can use it to size background queues and avoid oversubscription.
   *
   * @return configured maximum number of concurrent background USK fetchers.
   */
  @SuppressWarnings("unused")
  public int maxBackgroundUSKFetchers() {
    return maxBackgroundUSKFetchers;
  }

  /**
   * Returns whether a file path is permitted as a download target.
   *
   * <p>This check enforces the current physical threat level and the configured download allowlist,
   * including the downloads directory when enabled. If downloads are disabled by configuration, no
   * target is accepted. The check uses parent-path matching and does not create directories or
   * touch the filesystem beyond path comparisons.
   *
   * @param filename target file path to validate against download allowlist.
   * @return {@code true} if the path is allowed under current policy.
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
   * Returns whether a file path is permitted as an upload source.
   *
   * <p>This check uses the configured upload allowlist and does not verify file existence. The
   * result is a snapshot of current configuration and is used to gate upload requests before any
   * I/O occurs. Paths are matched by parent-directory containment. The method does not read file
   * contents and only evaluates path hierarchy.
   *
   * @param filename source file path to validate against upload allowlist.
   * @return {@code true} if the path is allowed as an upload source.
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

  /**
   * Returns the current allowlist for download destinations.
   *
   * <p>The returned array contains the configured directories used for permission checks. It is a
   * direct reference to internal state, so callers should not modify the array or its elements. The
   * allowlist may be empty when downloads are disabled. No defensive copy is made.
   *
   * @return current allowlist array; entries are internal references, not copies.
   */
  public synchronized File[] getAllowedDownloadDirs() {
    return downloadAllowedDirs;
  }

  /**
   * Returns the current allowlist for upload sources.
   *
   * <p>The returned array contains the configured directories used for permission checks. It is a
   * direct reference to internal state, so callers should not modify the array or its elements. The
   * allowlist may be empty when no explicit sources are configured. No defensive copy is made.
   *
   * @return current allowlist array; entries are internal references, not copies.
   */
  public synchronized File[] getAllowedUploadDirs() {
    return uploadAllowedDirs;
  }

  /**
   * Serializes client throttle state to a field set for persistence.
   *
   * <p>The returned {@link SimpleFieldSet} captures the current throttling configuration for
   * request starters and schedulers so it can be written to persistent storage. The snapshot is
   * intended for persistence and reload, not for direct mutation by callers. The method performs no
   * I/O and only builds an in-memory structure.
   *
   * @return throttles encoded as a {@link SimpleFieldSet} snapshot for persistence.
   */
  @Override
  public SimpleFieldSet persistThrottlesToFieldSet() {
    return requestStarters.persistToFieldSet();
  }

  /**
   * Returns the directory used for persistent temporary buckets.
   *
   * <p>This directory is created during initialization and is used for restart-safe temporary
   * storage. The returned {@link File} is the internal instance used by the core, so callers should
   * treat it as shared and avoid changing its contents outside managed cleanup. The accessor
   * performs no I/O and returns the current configuration value.
   *
   * @return directory used for persistent temporary bucket storage.
   */
  public File getPersistentTempDir() {
    return persistentTempDir;
  }

  /**
   * Returns the directory used for ephemeral temporary buckets.
   *
   * <p>This directory is created during initialization and is used for short-lived temporary
   * storage. The returned {@link File} is the internal instance used by the core, so callers should
   * treat it as shared and avoid changing its contents outside managed cleanup. The accessor
   * performs no I/O and returns the current configuration value.
   *
   * @return directory used for non-persistent temporary bucket storage.
   */
  public File getTempDir() {
    return tempDir;
  }

  /**
   * Queues a key that has been offered by peers to be fetched opportunistically.
   *
   * <p>The key is placed on the scheduler corresponding to its type (SSK vs CHK) and the selected
   * real-time or bulk queue. This operation is asynchronous; it only enqueues the key and returns.
   * It is typically used when peers advertise availability via offered-key mechanisms.
   *
   * @param key offered key to enqueue for opportunistic fetching.
   * @param realTime whether to enqueue on the real-time scheduler.
   */
  public void queueOfferedKey(Key key, boolean realTime) {
    requestStarters
        .getScheduler(key instanceof NodeSSK, false, realTime)
        .queueOfferedKey(key, realTime);
  }

  /**
   * Removes a previously queued offered key from both bulk and real-time schedulers.
   *
   * <p>The removal is applied to both queue variants to avoid stale scheduling. If the key is not
   * present, the operation has no observable effect and returns immediately. The method does not
   * block on network activity or disk I/O. It only updates scheduler queues in memory.
   *
   * @param key offered key to remove from scheduler queues.
   */
  public void dequeueOfferedKey(Key key) {
    requestStarters.getScheduler(key instanceof NodeSSK, false, false).dequeueOfferedKey(key);
    requestStarters.getScheduler(key instanceof NodeSSK, false, true).dequeueOfferedKey(key);
  }

  /**
   * Returns the total number of requests currently queued across schedulers.
   *
   * <p>The count includes both real-time and bulk queues for CHK and SSK schedulers. The value is a
   * snapshot of current state and can change immediately as requests are queued or completed. The
   * method performs no blocking operations and returns immediately.
   *
   * @return total queued request count across all schedulers.
   */
  public long countQueuedRequests() {
    return requestStarters.countQueuedRequests();
  }

  /**
   * Returns the global cap on background USK fetchers.
   *
   * <p>This static value is loaded from configuration during initialization. It is used by USK
   * scheduling to limit concurrent background fetch activity across the node. The accessor performs
   * no I/O and returns the current configured value. Callers typically use it to size background
   * queues and avoid oversubscription.
   *
   * @return configured maximum number of background USK fetchers.
   */
  public static int getMaxBackgroundUSKFetchers() {
    return maxBackgroundUSKFetchers;
  }

  // Security note: If tunneling or similar distance-start mechanisms are introduced,
  // revisit this behavior. See RequestHandler onAbort() handler.
  /**
   * Returns whether any fetch scheduler wants the given key.
   *
   * <p>The method checks both real-time and bulk fetch schedulers for the key type (SSK vs CHK). It
   * is used to decide whether to keep or forward offered keys and to avoid redundant work. The
   * result is a snapshot and may change as scheduling state evolves.
   *
   * @param key key to test for scheduler interest.
   * @return {@code true} if any scheduler currently wants the key.
   */
  public boolean wantKey(Key key) {
    boolean isSSK = key instanceof NodeSSK;
    if (this.clientContext.getFetchScheduler(isSSK, true).wantKey(key)) return true;
    return this.clientContext.getFetchScheduler(isSSK, false).wantKey(key);
  }

  /**
   * Estimates the recency of failures for routing decisions.
   *
   * <p>This performs a local probe equivalent to how {@link RequestSender} considers recent
   * failures for a key at the originator, ensuring comparable behavior to running requests. The
   * returned value is an internal metric and should only be used for relative comparisons in
   * routing heuristics, not for display.
   *
   * @param key target key to probe for recent failures.
   * @param realTime whether to use real-time routing heuristics or bulk.
   * @return non-negative value indicating how recently the key failed.
   */
  public long checkRecentlyFailed(Key key, boolean realTime) {
    return NodeClientCoreSupport.checkRecentlyFailed(node, key, realTime);
  }

  /**
   * Returns the plugin stores accessor for this node.
   *
   * <p>The returned {@link PluginStores} instance provides access to plugin-managed storage and is
   * created during core initialization. It is shared across the node lifecycle, so callers should
   * treat it as core-owned and avoid replacing or shutting it down directly. The accessor performs
   * no I/O and returns the existing instance.
   *
   * @return shared {@link PluginStores} instance used for plugin storage.
   */
  public PluginStores getPluginStores() {
    return pluginStores;
  }

  /**
   * Returns the minimum free-disk threshold for long-running jobs, in bytes.
   *
   * <p>This value is configured via node settings and is used to gate operations with unpredictable
   * duration, such as large downloads. The value is a snapshot and may change when configuration is
   * updated at runtime. The accessor performs no I/O and returns the current threshold.
   *
   * @return minimum free-disk threshold for long-running jobs, in bytes.
   */
  public synchronized long getMinDiskFreeLongTerm() {
    return minDiskFreeLongTerm;
  }

  /**
   * Returns the minimum free-disk threshold for short, disk-heavy jobs, in bytes.
   *
   * <p>This value is configured via node settings and is used to gate operations such as completing
   * downloads. The value is a snapshot and may change when configuration is updated at runtime. The
   * accessor performs no I/O and returns the current threshold.
   *
   * @return minimum free-disk threshold for short disk-heavy jobs, in bytes.
   */
  public synchronized long getMinDiskFreeShortTerm() {
    return minDiskFreeShortTerm;
  }

  /**
   * Returns whether the client-layer database has been killed or not loaded.
   *
   * <p>This reflects the {@link ClientLayerPersister} state and indicates whether persistence is
   * unavailable for client-layer data. It can be used to gate operations that require persisted
   * state or to display warnings in UI surfaces. The accessor performs no I/O and simply reflects
   * persister state.
   *
   * @return {@code true} if persistence is unavailable for client-layer data.
   */
  public boolean killedDatabase() {
    return this.getClientLayerPersister().isKilledOrNotLoaded();
  }

  /**
   * Returns the set of currently persisted FCP requests.
   *
   * <p>The returned array is a snapshot of persisted request state at the time of the call. It may
   * be empty if persistence is disabled or if no requests are stored. Callers should treat the
   * array as read-only. The accessor performs no I/O and returns the in-memory snapshot.
   *
   * @return snapshot array of persisted {@link ClientRequest} entries.
   */
  public ClientRequest[] getPersistentRequests() {
    return persistence.getPersistentRequests();
  }

  /**
   * Installs the persistent master secret for encrypted resources and factories.
   *
   * <p>If the client context does not already have a persistent secret, this method installs the
   * provided secret and wires it into the persistent temp bucket factory and RAF persistence. It
   * does not generate a secret; callers must supply one that is already initialized.
   *
   * @param persistentSecret master secret to use for persistent encryption state.
   */
  public void setupMasterSecret(MasterSecret persistentSecret) {
    if (getClientContext().getPersistentMasterSecret() == null)
      getClientContext().setPersistentMasterSecret(persistentSecret);
    getPersistentTempBucketFactory().setMasterSecret(persistentSecret);
    persistence.setPersistentRafMasterSecret(persistentSecret);
  }

  /**
   * Returns whether the client-layer database has been loaded.
   *
   * <p>This reflects whether the {@link ClientLayerPersister} has completed loading persistent
   * state. It can be used to gate operations that depend on restored request queues or throttles.
   * The accessor performs no I/O and simply reflects persister state. It does not trigger loading
   * and does not alter persistence state.
   *
   * @return {@code true} if the client-layer database has been loaded.
   */
  public boolean loadedDatabase() {
    return getClientLayerPersister().hasLoaded();
  }

  /**
   * Returns the USK manager.
   *
   * <p>The returned {@link USKManager} instance coordinates USK state and scheduling for this core.
   * It is initialized during construction and is shared for the life of the node, so callers should
   * treat it as core-owned. The accessor performs no I/O and returns the existing instance.
   *
   * @return shared {@link USKManager} instance for this core.
   */
  public USKManager getUskManager() {
    return uskManager;
  }

  /**
   * Returns the group of request starters and schedulers.
   *
   * <p>The {@link RequestStarterGroup} coordinates routing, throttling, and queue management for
   * both fetch and insert operations. The returned instance is shared and should be treated as
   * core-owned state managed by the node lifecycle. The accessor performs no I/O and returns the
   * existing instance.
   *
   * @return shared {@link RequestStarterGroup} coordinating request starts.
   */
  public RequestStarterGroup getRequestStarters() {
    return requestStarters;
  }

  /**
   * Returns the anti-CSRF token expected by HTTP handlers.
   *
   * <p>The token is generated during initialization and is used by HTTP forms to protect
   * state-changing requests. Callers should treat it as sensitive within UI contexts and avoid
   * exposing it outside expected request handling flows. The accessor performs no I/O and returns
   * the stored token.
   *
   * @return anti-CSRF token string used by HTTP handlers and forms.
   */
  public String getFormPassword() {
    return formPassword;
  }

  /**
   * Returns the factory for ephemeral temporary buckets.
   *
   * <p>The returned {@link TempBucketFactory} manages non-persistent temporary storage for client
   * operations. It is configured during initialization and shared across requests, so callers
   * should avoid modifying its lifecycle outside managed shutdown. The accessor performs no I/O and
   * returns the existing instance.
   *
   * @return shared {@link TempBucketFactory} for ephemeral buckets.
   */
  public TempBucketFactory getTempBucketFactory() {
    return tempBucketFactory;
  }

  /**
   * Returns the factory for persistent temporary buckets.
   *
   * <p>The returned {@link PersistentTempBucketFactory} manages restart-safe temporary storage for
   * client operations. It is configured during initialization and shared across requests, so
   * callers should avoid modifying its lifecycle outside managed shutdown. The accessor performs no
   * I/O and returns the existing instance.
   *
   * @return shared {@link PersistentTempBucketFactory} for persistent buckets.
   */
  public PersistentTempBucketFactory getPersistentTempBucketFactory() {
    return persistentTempBucketFactory;
  }

  /**
   * Returns the client-layer persister.
   *
   * <p>The {@link ClientLayerPersister} is responsible for loading and saving client-layer state
   * such as throttles and persistent requests. The returned instance is shared and should be
   * treated as core-owned service infrastructure. The accessor performs no I/O and returns the
   * existing instance.
   *
   * @return shared {@link ClientLayerPersister} instance for persistence.
   */
  public ClientLayerPersister getClientLayerPersister() {
    return clientLayerPersister;
  }

  /**
   * Returns the owning node.
   *
   * <p>This provides access to the {@link Node} that created and owns this core. The node manages
   * lifecycle and executor resources, so callers should treat it as shared and avoid altering its
   * state except through supported APIs. The accessor performs no I/O and returns the existing
   * instance.
   *
   * @return owning {@link Node} instance for this core.
   */
  public Node getNode() {
    return node;
  }

  /**
   * Returns the non-cryptographic random source used by this component.
   *
   * <p>The returned {@link RandomSource} is used for request IDs and other non-cryptographic needs.
   * It is shared across the core and should not be replaced or reseeded by callers. The accessor
   * performs no I/O and returns the existing instance. Use it only for non-cryptographic purposes.
   *
   * @return shared non-cryptographic {@link RandomSource} used by the core.
   */
  public RandomSource getRandom() {
    return random;
  }

  /**
   * Returns the user-alert manager.
   *
   * <p>The returned {@link UserAlertManager} coordinates user-facing alerts emitted by client
   * components. It is created during initialization and shared for the life of the node. The
   * accessor performs no I/O and returns the existing instance. Use it to register or clear alerts
   * as needed by client-facing components.
   *
   * @return shared {@link UserAlertManager} instance used for alerts.
   */
  public UserAlertManager getAlerts() {
    return alerts;
  }

  /**
   * Returns the datastore consistency checker.
   *
   * <p>The {@link DatastoreChecker} validates datastore health and is started during core startup.
   * The returned instance is shared and should be treated as core-owned service state. The accessor
   * performs no I/O and returns the existing instance. Use it to coordinate datastore checking
   * tasks when needed.
   *
   * @return shared {@link DatastoreChecker} instance for datastore checks.
   */
  public DatastoreChecker getStoreChecker() {
    return storeChecker;
  }

  /**
   * Returns the client context shared with higher-level client APIs.
   *
   * <p>The {@link ClientContext} bundles shared configuration, caches, and schedulers used by
   * client requests. It is created during construction and is central to request execution, so
   * callers should treat it as shared, mutable state managed by the core. The accessor performs no
   * I/O and returns the existing instance.
   *
   * @return shared {@link ClientContext} instance used by client APIs.
   */
  public ClientContext getClientContext() {
    return clientContext;
  }
}
