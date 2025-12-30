package network.crypta.node;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashSet;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FECCodec;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.InsertContext;
import network.crypta.client.async.HealingDecisionSupplier;
import network.crypta.client.async.SimpleHealingQueue;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.crypt.RandomSource;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.DatastoreTooSmallAlert;
import network.crypta.node.useralerts.DiskSpaceUserAlert;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.LongCallback;
import network.crypta.support.compress.Compressor;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.TempBucketFactory;

/** Helper methods that keep NodeClientCore wiring focused while preserving existing behavior. */
public final class NodeClientCoreSupport {
  /** Lock used when evaluating persistence alert validity to avoid synchronizing on parameters. */
  private static final Object PERSISTENCE_ALERT_LOCK = new Object();

  private NodeClientCoreSupport() {}

  /** Returns the default cache directory for the current environment (service or desktop). */
  public static File resolveDefaultCacheDir() {
    return resolveDefaultDirs().getCacheDir().toFile();
  }

  /** Returns the default data directory for the current environment (service or desktop). */
  public static File resolveDefaultDataDir() {
    return resolveDefaultDirs().getDataDir().toFile();
  }

  /** Returns the resolved program directory as a {@link File}. */
  public static File setupProgramDirFile(
      Node node,
      SubConfig installConfig,
      String cfgKey,
      String defaultValue,
      String shortDesc,
      String longDesc)
      throws NodeInitException {
    return setupProgramDirFile(
        node, installConfig, cfgKey, defaultValue, shortDesc, longDesc, null);
  }

  /** Returns the resolved program directory as a {@link File}. */
  public static File setupProgramDirFile(
      Node node,
      SubConfig installConfig,
      String cfgKey,
      String defaultValue,
      String shortDesc,
      String longDesc,
      String moveErrMsg)
      throws NodeInitException {
    return node.setupProgramDir(
            installConfig, cfgKey, defaultValue, shortDesc, longDesc, moveErrMsg)
        .dir();
  }

  /** Creates archive and healing resources required for client context initialization. */
  public static ClientContextResources createClientContextResources(
      Node node,
      TempBucketFactory tempBucketFactory,
      int maxArchiveHandlers,
      long maxCachedArchiveData,
      long maxArchivedFileSize,
      int maxCachedElements,
      int maxRunningHealingInserts) {
    ArchiveManager archiveManager =
        new ArchiveManager(
            maxArchiveHandlers,
            maxCachedArchiveData,
            maxArchivedFileSize,
            maxCachedElements,
            tempBucketFactory);
    SimpleHealingQueue healingQueue =
        new SimpleHealingQueue(
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
            maxRunningHealingInserts,
            new HealingDecisionSupplier(node::getLocation, node::isOpennetEnabled));
    return new ClientContextResources(archiveManager, healingQueue);
  }

  /**
   * Creates a high-level client bound to the provided core.
   *
   * <p>The returned client shares the core's context and bucket factories and honors the provided
   * priority class and real-time flag.
   */
  public static HighLevelSimpleClient createHighLevelClient(
      NodeClientCore core,
      TempBucketFactory tempBucketFactory,
      RandomSource random,
      short prioClass,
      boolean forceDontIgnoreTooManyPathComponents,
      boolean realTimeFlag) {
    return new HighLevelSimpleClientImpl(
        core,
        tempBucketFactory,
        random,
        prioClass,
        forceDontIgnoreTooManyPathComponents,
        realTimeFlag);
  }

  /**
   * Computes the default memory limit for memory-limited jobs given the overall JVM memory limit.
   *
   * <p>The default starts at the minimum required by FEC decoding and scales with available memory
   * beyond 512 MiB. This mirrors the previous in-core calculation and keeps the same effective
   * defaults.
   *
   * @param overallMemoryLimit total memory limit in bytes.
   * @return computed default memory limit for memory-limited jobs.
   */
  public static long computeDefaultMemoryLimitedJobMemoryLimit(long overallMemoryLimit) {
    long limit = FECCodec.MIN_MEMORY_ALLOCATION;
    if (overallMemoryLimit > 512L * 1024 * 1024) {
      limit += (overallMemoryLimit - 512L * 1024 * 1024) / 20;
    }
    return limit;
  }

  /**
   * Registers the memory-limited job memory cap setting.
   *
   * <p>Validation enforces the minimum FEC allocation and updates the shared runner at runtime.
   *
   * @param init initialization context containing node configuration.
   * @param sortOrder current config sort order.
   * @param defaultMemoryLimitedJobMemoryLimit default memory cap in bytes.
   * @param core owning core used to access the shared runner.
   * @return updated sort order.
   */
  public static int registerMemoryLimitedJobMemoryLimit(
      NodeClientCoreInit init,
      int sortOrder,
      long defaultMemoryLimitedJobMemoryLimit,
      NodeClientCore core) {
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
                return core.memoryLimitedJobRunner.getCapacity();
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
                core.memoryLimitedJobRunner.setCapacity(val);
              }
            },
            true);
    return sortOrder + 1;
  }

  /** Builds a client CHK block from an encoded block and key. */
  public static ClientKeyBlock buildClientChkBlock(CHKBlock block, ClientCHK key)
      throws CHKVerifyException {
    return new ClientCHKBlock(block, key);
  }

  /** Builds a client CHK block from raw data and headers. */
  public static ClientKeyBlock buildClientChkBlock(byte[] data, byte[] header, ClientCHK key)
      throws CHKVerifyException {
    return new ClientCHKBlock(data, header, key, true);
  }

  /** Builds a client SSK block from an encoded block and key. */
  public static ClientKeyBlock buildClientSskBlock(SSKBlock block, ClientSSK key)
      throws SSKVerifyException {
    return ClientSSKBlock.construct(block, key);
  }

  /**
   * Builds CHK insert options for the local insert path.
   *
   * <p>This creates the {@link PartiallyReceivedBlock} wrapper and applies the same option
   * configuration previously assembled in {@link NodeClientCore}.
   */
  public static Node.ChkInsertOptions buildChkInsertOptions(
      byte[] headers,
      byte[] data,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean preferInsert,
      boolean ignoreLowBackoff,
      boolean realTimeFlag) {
    PartiallyReceivedBlock prb =
        new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE, data);
    return Node.ChkInsertOptions.of(headers, prb)
        .withFromStore(false)
        .withCanWriteClientCache(canWriteClientCache)
        .withForkOnCacheable(forkOnCacheable)
        .withPreferInsert(preferInsert)
        .withIgnoreLowBackoff(ignoreLowBackoff)
        .withRealTimeFlag(realTimeFlag);
  }

  /**
   * Deletes the provided file, mirroring NodeClientCore's previous deletion behavior.
   *
   * @throws IOException if deletion fails
   */
  public static void deleteFile(File file) throws IOException {
    Files.delete(file.toPath());
  }

  /**
   * Computes the most recent failure timing for routing decisions.
   *
   * <p>Mirrors the originator behavior by decrementing HTL before invoking the routing selector.
   */
  public static long checkRecentlyFailed(Node node, Key key, boolean realTime) {
    RecentlyFailedReturn result = new RecentlyFailedReturn();
    short origHtl = node.decrementHTL(null, node.maxHTL());
    node.getPeers()
        .routingSelector()
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
            origHtl,
            0,
            true,
            realTime,
            result,
            false,
            System.currentTimeMillis(),
            node.enableNewLoadManagement(realTime));
    return result.recentlyFailed();
  }

  /** Creates the startup alert displayed until the node finishes initialization. */
  public static UserAlert createStartingUpAlert(String title, String longText, String shortText) {
    return new SimpleUserAlert(true, title, longText, shortText, UserAlert.ERROR);
  }

  /** Registers the core FProxy alerts, including the persistence-broken warning. */
  public static void registerFProxyAlerts(
      UserAlertManager alerts, NodeClientCore core, UserAlert startingUpAlert) {
    alerts.register(startingUpAlert);
    alerts.register(createPersistenceBrokenAlert(core));
  }

  /** Registers disk-space related user alerts. */
  public static void registerStorageAlerts(UserAlertManager alerts, NodeClientCore core) {
    alerts.register(new DiskSpaceUserAlert(core));
    alerts.register(new DatastoreTooSmallAlert(core));
  }

  /**
   * Returns a localized string for NodeClientCore settings.
   *
   * <p>Use {@link NodeL10n#getBase()} directly when parameter substitution is required.
   */
  public static String l10n(String key) {
    return NodeL10n.getBase().getString("NodeClientCore." + key);
  }

  private static UserAlert createPersistenceBrokenAlert(NodeClientCore core) {
    Node node = core.getNode();
    String tempDir =
        new File(FileUtil.getCanonicalFile(core.getPersistentTempDir()), File.separator).toString();
    String dbFile = new File(FileUtil.getCanonicalFile(node.getUserDir()), "client.dat").toString();
    return new SimpleUserAlert(
        true,
        NodeL10n.getBase().getString("QueueToadlet.persistenceBrokenTitle"),
        NodeL10n.getBase()
            .getString(
                "QueueToadlet.persistenceBroken",
                new String[] {"TEMPDIR", "DBFILE"},
                new String[] {tempDir, dbFile}),
        NodeL10n.getBase().getString("QueueToadlet.persistenceBrokenShortAlert"),
        UserAlert.CRITICAL_ERROR) {
      @Override
      public boolean isValid() {
        synchronized (PERSISTENCE_ALERT_LOCK) {
          if (!core.killedDatabase()) return false;
        }
        if (node.awaitingPassword()) return false;
        return !node.isStopping();
      }

      @Override
      public boolean userCanDismiss() {
        return false;
      }
    };
  }

  private static Resolved resolveDefaultDirs() {
    AppEnv appEnv = new AppEnv();
    return appEnv.isServiceMode() ? new ServiceDirs().resolve() : new AppDirs().resolve();
  }
}
