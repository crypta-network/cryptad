package network.crypta.node;

import java.io.File;
import java.io.IOException;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.USKManager;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.keys.NodeSSK;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.Base64;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
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
 * run on node executor threads; accessors that expose the mutable configuration state are
 * synchronized to provide a stable snapshot.
 *
 * <p>State is mostly immutable after construction, with explicit setters for download and upload
 * allowlists and disk-threshold configuration. The node lifecycle owns Long-lived services such as
 * the persister, request starters, and datastore checker; callers get shared references but should
 * not shut them down directly. Thread-safety is achieved via final fields, synchronized accessors
 * for mutable policy, and executor-managed background tasks rather than external locking.
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
public final class NodeClientCore implements Persistable {
  private static final Logger LOG = LoggerFactory.getLogger(NodeClientCore.class);
  private static final String CFG_ENCRYPT_PERSISTENT_TEMP_BUCKETS = "encryptPersistentTempBuckets";
  private static final String DOWNLOADS_DIR_NAME = "downloads";
  // Maximum number of healing inserts. If a 320 MiB file barely succeeds,
  // it has ~10,000 blocks eligible for healing (10,000 × 32 KiB).
  // Large-file lifetime is currently 7–14 days; with a 10,000-key cap, a 320 MiB file
  // stays alive if one person accesses it every 10 days, and a 3 GiB file if one person
  // downloads it per day. 8k inserts can require up to ~250 MiB when large files just
  // barely succeed.
  private static final int MAX_RUNNING_HEALING_INSERTS = 8192;

  /** Manages USK state. Access via {@link #getUskManager()}. */
  private final USKManager uskManager;

  /** Request starter group. Access via {@link #getRequestStarters()}. */
  private final RequestStarterGroup requestStarters;

  /** Fetch/insert operations bound to this core. Access via {@link #getTransfers()}. */
  private final NodeClientCoreTransfers transfers;

  /**
   * Runs memory-bounded background jobs such as FEC decoding.
   *
   * <p>The runner enforces configured memory and thread ceilings for long-lived background work
   * shared across client operations. It is owned by the core for the node lifetime, so callers
   * should not shut it down or reconfigure limits outside the managed settings callbacks.
   */
  public final MemoryLimitedJobRunner memoryLimitedJobRunner;

  /**
   * Anti-CSRF token used by the HTTP UI.
   *
   * <p>Include this value as a hidden field in any POST that changes server-side state and verify
   * it on receipt.
   */
  private final String formPassword;

  final File downloadsDir;
  private final NodeClientCoreTransferPolicy transferPolicy;

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
   * <p>The instance is created during construction and shared across requests for the lifetime of
   * the node. It is configured by the core and wired to the {@link ClientContext}; callers should
   * treat it as read-only infrastructure and avoid calling {@link RealCompressor#shutdown()}.
   */
  public final RealCompressor compressor;

  /** Datastore consistency checker. Access via {@link #getStoreChecker()}. */
  private final DatastoreChecker storeChecker;

  /**
   * How much disk space must be free when starting a long-term, unpredictable duration job such as
   * a big download?
   */
  private volatile long minDiskFreeLongTerm;

  /**
   * How much disk space must be free when starting a quick but disk-heavy job such as completing a
   * download?
   */
  private volatile long minDiskFreeShortTerm;

  /** Client context. Access via {@link #getClientContext()}. */
  private final ClientContext clientContext;

  private static int maxBackgroundUSKFetchers; // Client configuration item
  static final int MAX_ARCHIVE_HANDLERS = 200; // take up little RAM
  static final long MAX_CACHED_ARCHIVE_DATA =
      32L * 1024 * 1024; // consider proportional to store size by default
  static final long MAX_ARCHIVED_FILE_SIZE = 1024L * 1024; // arbitrary
  static final int MAX_CACHED_ELEMENTS =
      256 * 1024; // equally arbitrary; hopefully, we can cache many of these though
  private boolean alwaysCommit;
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
    this.random = node.bootstrap().random();

    sortOrder = registerLazyStartDatastoreChecker(init, sortOrder);

    storeChecker =
        new DatastoreChecker(
            node, lazyStartDatastoreChecker, node.network().executor(), "Datastore checker");
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

    // Remove the legacy persistent-blob file to reclaim space for migration.
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
            node.network().executor(),
            tempFilenameGenerator,
            init.nodeConfig().getLong("maxRAMBucketSize"),
            init.nodeConfig().getLong("RAMBucketPoolSize"),
            init.nodeConfig().getBoolean("encryptTempBuckets"),
            minDiskFreeShortTerm,
            cryptoSecretTransient);

    clientLayerPersister =
        new ClientLayerPersister(
            node.network().executor(),
            node.network().ticker(),
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
        NodeClientCoreSupport.computeDefaultMemoryLimitedJobMemoryLimit(overallMemoryLimit);
    sortOrder =
        NodeClientCoreSupport.registerMemoryLimitedJobMemoryLimit(
            init, sortOrder, defaultMemoryLimitedJobMemoryLimit, this);
    memoryLimitedJobRunner =
        new MemoryLimitedJobRunner(
            init.nodeConfig().getLong("memoryLimitedJobMemoryLimit"),
            init.nodeConfig().getInt("memoryLimitedJobThreadLimit"),
            node.network().executor(),
            RequestStarter.NUMBER_OF_PRIORITY_CLASSES);
    installFecShutdownHooks(shutdownHook);
    ClientContextInitParams clientContextParams =
        new ClientContextInitParams(
            clientLayerPersister,
            node.network().executor(),
            clientContextResources,
            persistentTempBucketFactory,
            tempBucketFactory,
            uskManager,
            random,
            node.bootstrap().fastWeakRandom(),
            node.network().ticker(),
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
    clientContext = persistence.createClientContext(node, clientContextParams);
    compressor.setClientContext(getClientContext());
    storeChecker.setContext(getClientContext());
    getClientLayerPersister().start(getClientContext());

    requestStarters = createRequestStarters(node, portNumber, init, throttleFS);
    transfers = new NodeClientCoreTransfers(this);

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
            NodeClientCoreSupport.l10n("couldNotFindOrCreateDir"));
    this.transferPolicy = new NodeClientCoreTransferPolicy(node, downloadsDir);

    // Downloads allowed, uploads allowed

    sortOrder = transferPolicy.registerDownloadAllowedDirs(init, sortOrder);

    sortOrder = transferPolicy.registerUploadAllowedDirs(init, sortOrder);

    LOG.info("Initializing USK Manager");
    uskManager.init(getClientContext());

    sortOrder = registerMaxBackgroundUSKFetchers(init, sortOrder);

    // This is all part of construction, not of start().
    // Create it early so all client-facing endpoints can rely on it during startup.

    // TMCI and FCP (including persistent requests so needs to start before FProxy)
    ClientEndpoints.InitResult endpointsInit =
        ClientEndpoints.create(node, this, init, persistence, clientContext);
    endpoints = endpointsInit.endpoints();
    TextModeClientInterface directTMCI = endpointsInit.directTMCI();
    if (directTMCI != null) {
      endpoints.setDirectTMCI(directTMCI);
      node.network().executor().execute(directTMCI, "Direct text mode interface");
    }

    // FProxy
    // Startup alerts are wired here so the HTTP layer can render early boot progress.
    endpoints.registerStartupAlerts(
        alerts,
        this,
        NodeClientCoreSupport.l10n("startingUpTitle"),
        NodeClientCoreSupport.l10n("startingUp"),
        NodeClientCoreSupport.l10n("startingUpShort"));
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
   * temporary data to disk. It synchronizes on this core to read the latest long-term threshold,
   * then applies the derived value only when a persistent factory is present. Calling it multiple
   * times with unchanged configuration is effectively idempotent and performs no I/O beyond the
   * factory update.
   */
  void updatePersistentRAFSpaceLimit() {
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
            new Option.Meta(
                sortOrder++,
                true,
                true,
                "NodeClientCore.minDiskFreeLongTerm",
                "NodeClientCore.minDiskFreeLongTermLong"),
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
                    throw new InvalidConfigValueException(
                        NodeClientCoreSupport.l10n("minDiskFreeMustBePositive"));
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
            new Option.Meta(
                sortOrder + 1,
                true,
                true,
                "NodeClientCore.minDiskFreeShortTerm",
                "NodeClientCore.minDiskFreeShortTermLong"),
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
                    throw new InvalidConfigValueException(
                        NodeClientCoreSupport.l10n("minDiskFreeMustBePositive"));
                  minDiskFreeShortTerm = val;
                }
                tempBucketFactory.setMinDiskSpace(val);
              }
            },
            true);
    minDiskFreeShortTerm = init.nodeConfig().getLong("minDiskFreeShortTerm");
    // Do not register the UserAlert yet, since we haven't finished constructing the stuff it uses.
  }

  /**
   * Performs the late database initialization phase once a master key is available.
   *
   * @param databaseKey optional database encryption key
   * @return {@code true} if initialization succeeded; {@code false} otherwise
   */
  public boolean lateInitDatabase(DatabaseKey databaseKey) {
    LOG.info("Late database initialisation: starting middle phase");
    if (initStorage(databaseKey)) {
      // Don't start the database thread yet, messy concurrency issues.
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

  /** Must only be called after we have loaded "master.keys" */
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

  // Note: Use NodeL10n.getBase().getString("NodeClientCore.<key>", pattern, value) directly
  // when parameter substitution is needed.

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
          node.bootstrap().fastWeakRandom(),
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
      LOG.info("Deleting legacy persistent blob file: {}", oldBlobFile);
      if (persistentTempBucketFactory.isEncrypting()) {
        try {
          FileUtil.secureDelete(oldBlobFile);
        } catch (IOException e) {
          LOG.warn(
              "Secure delete failed for legacy persistent blob file {}: {}",
              oldBlobFile,
              e.toString());
          LOG.warn("Manual cleanup needed for legacy persistent blob file {}.", oldBlobFile);
        }
      } else {
        try {
          NodeClientCoreSupport.deleteFile(oldBlobFile);
        } catch (IOException e) {
          LOG.warn(
              "Delete failed for legacy persistent blob file {}: {}", oldBlobFile, e.toString());
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

  private int computeMaxMemoryLimitedJobThreads() {
    int maxThreads = Runtime.getRuntime().availableProcessors() / 2;
    maxThreads = Math.min(maxThreads, node.network().stats().getThreadLimit() / 20);
    return Math.max(1, maxThreads);
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
    node.storage().setDatabaseAwaitingPassword();
  }

  private void installPhysicalThreatLevelListener() {
    node.services()
        .securityLevels()
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
    if (initStorage(NodeClientCore.this.getNode().storage().getDatabaseKey())) {
      return;
    }
    NodeClientCore.this.getNode().storage().setDatabaseAwaitingPassword();
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
            new Option.Meta(
                sortOrder,
                true,
                false,
                "NodeClientCore.maxUSKFetchers",
                "NodeClientCore.maxUSKFetchersLong"),
            new IntCallback() {

              @Override
              public Integer get() {
                return maxBackgroundUSKFetchers;
              }

              @Override
              public void set(Integer uskFetch) throws InvalidConfigValueException {
                if (uskFetch <= 0)
                  throw new InvalidConfigValueException(
                      NodeClientCoreSupport.l10n("maxUSKFetchersMustBeGreaterThanZero"));
                maxBackgroundUSKFetchers = uskFetch;
              }
            },
            false);
    maxBackgroundUSKFetchers = init.nodeConfig().getInt("maxBackgroundUSKFetchers");
    return sortOrder + 1;
  }

  private int registerMemoryLimitedJobThreadLimit(
      NodeClientCoreInit init, int sortOrder, int maxMemoryLimitedJobThreads) {
    init.nodeConfig()
        .register(
            "memoryLimitedJobThreadLimit",
            maxMemoryLimitedJobThreads,
            new Option.Meta(
                sortOrder,
                true,
                false,
                "NodeClientCore.memoryLimitedJobThreadLimit",
                "NodeClientCore.memoryLimitedJobThreadLimitLong"),
            new IntCallback() {

              @Override
              public Integer get() {
                return memoryLimitedJobRunner.getMaxThreads();
              }

              @Override
              public void set(Integer val) throws InvalidConfigValueException {
                if (val < 1)
                  throw new InvalidConfigValueException(
                      NodeClientCoreSupport.l10n("memoryLimitedJobThreadLimitMustBe1Plus"));
                memoryLimitedJobRunner.setMaxThreads(val);
              }
            },
            false);
    return sortOrder + 1;
  }

  @SuppressWarnings("UnusedReturnValue")
  private int registerAlwaysCommit(NodeClientCoreInit init, int sortOrder) {
    init.nodeConfig()
        .register(
            "alwaysCommit",
            false,
            new Option.Meta(
                sortOrder,
                true,
                false,
                "NodeClientCore.alwaysCommit",
                "NodeClientCore.alwaysCommitLong"),
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
            new Option.Meta(
                sortOrder,
                true,
                false,
                "NodeClientCore.maxRAMBucketSize",
                "NodeClientCore.maxRAMBucketSizeLong"),
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
            new Option.Meta(
                sortOrder,
                true,
                false,
                "NodeClientCore.ramBucketPoolSize",
                "NodeClientCore.ramBucketPoolSizeLong"),
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
            new Option.Meta(
                sortOrder,
                true,
                false,
                "NodeClientCore.encryptTempBuckets",
                "NodeClientCore.encryptTempBucketsLong"),
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
            new Option.Meta(
                sortOrder,
                true,
                false,
                "NodeClientCore.encryptPersistentTempBuckets",
                "NodeClientCore.encryptPersistentTempBucketsLong"),
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
    File oldTemp = node.runDir().file("temp-" + node.network().darknetPortNumber());
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
            new Option.Meta(
                sortOrder,
                true,
                false,
                "NodeClientCore.lazyStartDatastoreChecker",
                "NodeClientCore.lazyStartDatastoreCheckerLong"),
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
                        NodeClientCoreSupport.l10n("lazyStartDatastoreCheckerMustRestartNode"));
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
   * allowlisted path. The value is a snapshot and can change when the configuration is updated at
   * runtime.
   *
   * @return {@code true} if downloads are disabled and all targets are rejected.
   */
  public boolean isDownloadDisabled() {
    return transferPolicy.isDownloadDisabled();
  }

  /**
   * Configures directories where downloads may be written.
   *
   * <p>Recognized entries include {@code "all"} to allow any destination and {@code "downloads"} to
   * allow the configured "downloads" directory. Any other string is treated as a filesystem path
   * and stored as a {@link File}. Passing an empty array disables downloads entirely. The
   * configuration is applied immediately and affects later permission checks. The method updates
   * in-memory policy only, does not create directories, and does not validate that paths exist.
   * Reapplying the same list yields equivalent policy without additional side effects.
   *
   * @param val allowlist entries describing tokens or absolute/relative filesystem paths.
   */
  synchronized void setDownloadAllowedDirs(String[] val) {
    transferPolicy.setDownloadAllowedDirs(val);
  }

  /**
   * Configures directories from which uploads may read.
   *
   * <p>Recognized entries include {@code "all"} to allow any source. Any other string is treated as
   * a filesystem path and stored as a {@link File}. The configuration is applied immediately and
   * affects later permission checks for upload sources. The method performs no I/O and updates
   * in-memory policy. Calling it repeatedly with the same values is effectively idempotent, but
   * callers should provide normalized paths if they expect deterministic matching.
   *
   * @param val allowlist entries describing tokens or filesystem source paths.
   */
  synchronized void setUploadAllowedDirs(String[] val) {
    transferPolicy.setUploadAllowedDirs(val);
  }

  /**
   * Starts client-layer services and resumes persisted requests.
   *
   * <p>This method activates request starters, the datastore checker, and client endpoints, then
   * schedules a low-priority completion task to migrate persistent temporary buckets and resume
   * pending requests. Call it during node startup after construction has finished wiring.
   * Exceptions during migration are logged and do not prevent the remaining services from running.
   * The startup sequence is asynchronous: it returns immediately after scheduling the completion
   * task, so callers should not assume persistent requests are resumed when it returns. The method
   * is intended to be called once per node lifecycle.
   */
  public void start() {

    persistence.startThrottle();

    requestStarters.start();

    storeChecker.start();
    endpoints.maybeStart();
    node.network().ipDetector().ipDetectorManager.start();

    node.network()
        .executor()
        .execute(
            new PrioRunnable() {

              @Override
              public void run() {
                LOG.info("Resuming persistent requests");
                if (node.storage().getDatabaseKey() != null) {
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
   * Creates a high-level client bound to this core.
   *
   * <p>The returned client shares this core's {@link ClientContext}, bucket factories, and random
   * source so its requests are scheduled and accounted for with the node. The client respects the
   * provided priority class and real-time flag, which influence routing and throttling behavior.
   * This method does not start network activity by itself; it only constructs a configured client
   * instance. Repeated calls create independent client instances that share the same underlying
   * services and are safe to use concurrently.
   *
   * @param prioClass priority class assigned to requests issued by the client.
   * @param forceDontIgnoreTooManyPathComponents whether to disable pruning for overly long paths.
   * @param realTimeFlag true for latency-optimized requests, false for bulk requests.
   * @return configured client instance bound to this core and shared context.
   */
  public HighLevelSimpleClient makeClient(
      short prioClass, boolean forceDontIgnoreTooManyPathComponents, boolean realTimeFlag) {
    return NodeClientCoreSupport.createHighLevelClient(
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
   * shared across the node lifecycle. The accessor performs no I/O and returns the shared reference
   * immediately. Callers should treat it as core-owned and avoid stopping or reconfiguring
   * endpoints outside managed shutdown paths; the node lifecycle controls startup and shutdown.
   *
   * @return shared {@link ClientEndpoints} instance for the current node lifecycle.
   */
  public ClientEndpoints getEndpoints() {
    return endpoints;
  }

  /**
   * Returns the configured downloads directory.
   *
   * <p>The directory is resolved during initialization and represents the default location used
   * when downloads are permitted. The returned {@link File} is the internal instance used by the
   * core, so callers should treat it as shared and avoid mutating configuration through it. The
   * accessor performs no I/O and simply returns the current configuration snapshot.
   *
   * @return configured downloads directory {@link File} used by permission checks.
   */
  public File getDownloadsDir() {
    return downloadsDir;
  }

  /**
   * Persists the current configuration to disk.
   *
   * <p>This triggers the node configuration store to write its current values to the configured
   * storage location. The operation invokes the writing immediately, but the underlying storage
   * subsystem controls any buffering or durability semantics. Call it after changing configuration
   * values that must survive restart. The method is side-effecting, but it does not block on
   * network activity; any errors are handled by the configuration subsystem.
   */
  public void storeConfig() {
    LOG.info("Trying to write config to disk");
    node.getConfig().store();
  }

  /**
   * Returns whether the node runs in testnet mode.
   *
   * <p>This is a global setting that affects network compatibility and routing behavior. The value
   * is determined by node configuration and is not modified by this method. The accessor performs
   * no I/O and does not cache beyond the call, so changes in configuration are reflected on later
   * invocations. Use it to gate features or UI elements that should only operate on a test network.
   * The method is thread-safe and side-effect-free.
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
   * the current flag, making it safe to call from UI rendering code. It has no side effects and
   * does not influence the endpoint state.
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
   * change at runtime when the configuration is updated. The accessor performs no I/O and simply
   * returns the current flag; it does not alter rendering behavior by itself. Callers can use it to
   * decide whether to emit script-dependent UI elements.
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
   * custom name. The accessor performs no I/O and returns the current in-memory value; it does not
   * trigger configuration reloads. Callers should treat it as presentation data only.
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
   * background fetch activity. The value is a snapshot and can change if the configuration is
   * updated at runtime. The accessor performs no I/O and simply returns the current configuration
   * value. Callers can use it to size background queues and avoid oversubscription.
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
   * touch the filesystem beyond path comparisons. It is a pure policy check that can be called
   * frequently without side effects.
   *
   * @param filename file path to validate against the download allowlist.
   * @return {@code true} when the path is allowed by current policy.
   */
  public boolean allowDownloadTo(File filename) {
    return transferPolicy.allowDownloadTo(filename);
  }

  /**
   * Returns whether a file path is permitted as an upload source.
   *
   * <p>This check uses the configured upload allowlist and does not verify file existence. The
   * result is a snapshot of the current configuration and is used to gate upload requests before
   * any I/O occurs. Paths are matched by parent-directory containment. The method does not read
   * file contents and only evaluates path hierarchy. It is a pure policy check that has no side
   * effects.
   *
   * @param filename file path to validate against the upload allowlist.
   * @return {@code true} when the path is allowed as an upload source.
   */
  public synchronized boolean allowUploadFrom(File filename) {
    return transferPolicy.allowUploadFrom(filename);
  }

  /**
   * Returns the current allowlist for download destinations.
   *
   * <p>The returned array contains the configured directories used for permission checks. It is a
   * direct reference to the internal state, so callers should not modify the array or its elements.
   * The allowlist may be empty when downloads are disabled. No defensive copy is made, and the
   * reference may change when the configuration is updated.
   *
   * @return the current allowlist array with shared directory references and entries.
   */
  public synchronized File[] getAllowedDownloadDirs() {
    return transferPolicy.getAllowedDownloadDirs();
  }

  /**
   * Returns the current allowlist for upload sources.
   *
   * <p>The returned array contains the configured directories used for permission checks. It is a
   * direct reference to the internal state, so callers should not modify the array or its elements.
   * The allowlist may be empty when no explicit sources are configured. No defensive copy is made,
   * and the reference may change when the configuration is updated.
   *
   * @return the current allowlist array with shared directory references and entries.
   */
  public synchronized File[] getAllowedUploadDirs() {
    return transferPolicy.getAllowedUploadDirs();
  }

  /**
   * Serializes client throttle state to a field set for persistence.
   *
   * <p>The returned {@link SimpleFieldSet} captures the current throttling configuration for
   * request starters and schedulers so it can be written to persistent storage. The snapshot is
   * intended for persistence and reload, not for direct mutation by callers. The method performs no
   * I/O and only builds an in-memory structure. Calling it repeatedly without changing throttles is
   * effectively idempotent and produces equivalent output. It is safe to call from executor threads
   * as part of periodic persistence.
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
   * performs no I/O and returns the current configuration value, which can change only via
   * configuration updates.
   *
   * @return directory used for persistent temporary bucket storage on disk.
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
   * performs no I/O and returns the current configuration value, which can change only via
   * configuration updates.
   *
   * @return directory used for non-persistent temporary bucket storage on disk.
   */
  public File getTempDir() {
    return tempDir;
  }

  /**
   * Queues a key that peers have offered to be fetched opportunistically.
   *
   * <p>The key is placed on the scheduler corresponding to its type (SSK vs. CHK) and the selected
   * real-time or bulk queue. This operation is asynchronous; it only enqueues the key and returns.
   * It is typically used when peers advertise availability via offered-key mechanisms. Behavior for
   * already-queued keys is determined by the scheduler implementation. The method performs no
   * network I/O and returns immediately.
   *
   * @param key the offered key to enqueue for opportunistic fetching.
   * @param realTime true to enqueue on the real-time scheduler.
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
   * block on network activity or disk I/O. It only updates scheduler queues in memory, so repeated
   * calls are effectively idempotent.
   *
   * @param key the offered key to remove from scheduler queues.
   */
  public void dequeueOfferedKey(Key key) {
    requestStarters.getScheduler(key instanceof NodeSSK, false, false).dequeueOfferedKey(key);
    requestStarters.getScheduler(key instanceof NodeSSK, false, true).dequeueOfferedKey(key);
  }

  /**
   * Returns the total number of requests currently queued across schedulers.
   *
   * <p>The count includes both real-time and bulk queues for CHK and SSK schedulers. The value is a
   * snapshot of the current state and can change immediately as requests are queued or completed.
   * The method performs no blocking operations and returns immediately, so it is suitable for
   * monitoring and UI counters. No guarantees are made about consistency across concurrent updates.
   *
   * @return total queued request count across all schedulers currently.
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
   * queues and avoid oversubscription. The value may change when the configuration is reloaded.
   *
   * @return configured maximum number of background USK fetchers allowed.
   */
  public static int getMaxBackgroundUSKFetchers() {
    return maxBackgroundUSKFetchers;
  }

  // Security note: If tunneling or similar distance-start mechanisms are introduced,
  // revisit this behavior. See RequestHandler onAbort() handler.
  /**
   * Returns whether any fetch scheduler wants the given key.
   *
   * <p>The method checks both real-time and bulk fetch schedulers for the key type (SSK vs. CHK).
   * It is used to decide whether to keep or forward offered keys and to avoid redundant work. The
   * result is a snapshot and may change as the scheduling state evolves. The method performs no I/O
   * and does not enqueue the key; it only queries the scheduler state.
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
   * routing heuristics, not for display. The method performs no network I/O and returns
   * immediately.
   *
   * @param key target key to probe for recent failures.
   * @param realTime whether to use real-time routing heuristics or bulk.
   * @return non-negative value indicating how recently the key failed.
   */
  public long checkRecentlyFailed(Key key, boolean realTime) {
    return NodeClientCoreSupport.checkRecentlyFailed(node, key, realTime);
  }

  /**
   * Returns the minimum free-disk threshold for long-running jobs, in bytes.
   *
   * <p>This value is configured via node settings and is used to gate operations with unpredictable
   * duration, such as large downloads. The value is a snapshot and may change when the
   * configuration is updated at runtime. The accessor is synchronized to provide a consistent view
   * with other disk limit updates and performs no I/O. Use it to decide whether to admit
   * long-running requests.
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
   * downloads. The value is a snapshot and may change when the configuration is updated at runtime.
   * The accessor is synchronized to provide a consistent view with other disk limit updates and
   * performs no I/O. Use it to decide whether to admit short, disk-intensive work.
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
   * the persister state; it is a snapshot and may change as persistence loads or shuts down.
   *
   * @return {@code true} if persistence is unavailable for client-layer data.
   */
  public boolean killedDatabase() {
    return this.getClientLayerPersister().isKilledOrNotLoaded();
  }

  /**
   * Returns the set of currently persisted FCP requests.
   *
   * <p>The returned array is a snapshot of the persisted request state at the time of the call. It
   * may be empty if persistence is disabled or if no requests are stored. Callers should treat the
   * array as read-only and avoid modifying its elements. The accessor performs no I/O and returns
   * the in-memory snapshot immediately.
   *
   * @return snapshot array of persisted {@link ClientRequest} entries at call time.
   */
  public ClientRequest[] getPersistentRequests() {
    return persistence.getPersistentRequests();
  }

  /**
   * Installs the persistent master secret for encrypted resources and factories.
   *
   * <p>If the client context does not already have a persistent secret, this method installs the
   * provided secret and wires it into the persistent temp bucket factory and RAF persistence. It
   * does not generate a secret; callers must supply one that is already initialized. The method
   * performs no I/O and does not validate the secret beyond wiring it into dependent components.
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
   * The accessor performs no I/O and simply reflects the persister state. It does not trigger
   * loading and does not alter the persistence state; callers should poll or listen for updates as
   * needed.
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
   * treat it as core-owned. The accessor performs no I/O and returns the existing instance, which
   * may be used concurrently by multiple request paths.
   *
   * @return shared {@link USKManager} instance for this core.
   */
  public USKManager getUskManager() {
    return uskManager;
  }

  /**
   * Returns the client transfer operations for fetch/insert paths.
   *
   * <p>The returned {@link NodeClientCoreTransfers} instance encapsulates key transfer logic and is
   * bound to this core. Callers should treat it as a core-owned state and avoid replacing or
   * shutting it down directly. The accessor performs no I/O and returns the existing instance.
   *
   * @return shared transfer operations instance bound to this core.
   */
  public NodeClientCoreTransfers getTransfers() {
    return transfers;
  }

  /**
   * Returns the group of request starters and schedulers.
   *
   * <p>The {@link RequestStarterGroup} coordinates routing, throttling, and queue management for
   * both fetch and insert operations. The returned instance is shared and should be treated as a
   * core-owned state managed by the node lifecycle. The accessor performs no I/O and returns the
   * existing instance, which may be accessed concurrently by multiple request paths.
   *
   * @return shared {@link RequestStarterGroup} coordinating request starts for this node.
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
   * the stored token immediately; it does not regenerate or rotate the value.
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
   * returns the existing instance, which may be used concurrently by client operations.
   *
   * @return shared {@link TempBucketFactory} for ephemeral buckets used by clients.
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
   * I/O and returns the existing instance, which may be used concurrently by client operations.
   *
   * @return shared {@link PersistentTempBucketFactory} for persistent buckets used by clients.
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
   * existing instance, which may be used concurrently by persistence-related components.
   *
   * @return shared {@link ClientLayerPersister} instance for client-layer persistence tasks here.
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
   * instance immediately.
   *
   * @return owning {@link Node} instance for this core and lifecycle.
   */
  public Node getNode() {
    return node;
  }

  /**
   * Returns the non-cryptographic random source used by this component.
   *
   * <p>The returned {@link RandomSource} is used for request IDs and other non-cryptographic needs.
   * It is shared across the core and should not be replaced or reseeded by callers. The accessor
   * performs no I/O and returns the existing instance. Use it only for non-cryptographic purposes
   * and assume concurrent access from multiple request paths.
   *
   * @return shared non-cryptographic {@link RandomSource} instance used by the core.
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
   * as needed by client-facing components, without attempting to manage its lifecycle directly.
   *
   * @return shared {@link UserAlertManager} instance used for client alerts lifecycle.
   */
  public UserAlertManager getAlerts() {
    return alerts;
  }

  /**
   * Returns the datastore consistency checker.
   *
   * <p>The {@link DatastoreChecker} validates datastore health and is started during core startup.
   * The returned instance is shared and should be treated as a core-owned service state. The
   * accessor performs no I/O and returns the existing instance. Use it to coordinate datastore
   * checking tasks when needed; the node manages lifecycle control.
   *
   * @return shared {@link DatastoreChecker} instance for datastore check tasks and lifecycle.
   */
  public DatastoreChecker getStoreChecker() {
    return storeChecker;
  }

  /**
   * Returns the client context shared with higher-level client APIs.
   *
   * <p>The {@link ClientContext} bundles shared configuration, caches, and schedulers used by
   * client requests. It is created during construction and is central to request execution, so
   * callers should treat it as a shared, mutable state managed by the core. The accessor performs
   * no I/O and returns the existing instance immediately; callers should not replace or shut it
   * down.
   *
   * @return shared {@link ClientContext} instance used by client APIs here.
   */
  public ClientContext getClientContext() {
    return clientContext;
  }
}
