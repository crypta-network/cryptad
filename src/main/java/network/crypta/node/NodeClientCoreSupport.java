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
import network.crypta.client.InsertContextOptions;
import network.crypta.client.async.HealingDecisionSupplier;
import network.crypta.client.async.SimpleHealingQueue;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
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
import network.crypta.node.subsystem.NodeRoutingSubsystem;
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

/**
 * Provides wiring helpers that keep {@link NodeClientCore} focused on orchestration logic.
 *
 * <p>This utility exposes stateless factories and registration helpers used during node startup and
 * client setup. It resolves default directories based on the runtime environment, builds client
 * context resources, assembles insert options, and wires user alerts and localization. The helpers
 * intentionally mirror previous in-core defaults to preserve behavior while keeping the
 * implementation centralized and testable. The class is safe to call from multiple threads because
 * it holds no mutable state; the only shared guard is a dedicated lock that protects
 * persistence-alert validity checks.
 *
 * <ul>
 *   <li>Maps configuration inputs to existing node setup methods.
 *   <li>Constructs client-facing helper objects with preserved defaults.
 *   <li>Registers alert wiring for storage and startup status.
 * </ul>
 *
 * @see NodeClientCore
 * @see Node
 */
public final class NodeClientCoreSupport {
  /** Lock used when evaluating persistence alert validity to avoid synchronizing on parameters. */
  private static final Object PERSISTENCE_ALERT_LOCK = new Object();

  private NodeClientCoreSupport() {}

  /**
   * Resolves the default cache directory for the current runtime environment.
   *
   * <p>This helper selects the appropriate directory layout by consulting the environment detector
   * and then returns the cache directory from the resolved layout. It does not create or validate
   * the directory; callers typically use it as a default when initializing configuration or when no
   * explicit override is provided.
   *
   * @return default cache directory for the current environment, as a {@link File}.
   */
  public static File resolveDefaultCacheDir() {
    return resolveDefaultDirs().getCacheDir().toFile();
  }

  /**
   * Resolves the default data directory for the current runtime environment.
   *
   * <p>This helper chooses between service-mode and desktop directory layouts and then returns the
   * data directory from the resolved layout. It does not create or validate the directory; it
   * simply exposes the conventional location used by the node when a configuration override is
   * absent.
   *
   * @return default data directory for the current environment, as a {@link File}.
   */
  public static File resolveDefaultDataDir() {
    return resolveDefaultDirs().getDataDir().toFile();
  }

  /**
   * Resolves the program directory from configuration and returns it as a {@link File}.
   *
   * <p>This overload delegates to the full variant with a {@code null} move-error message. It is
   * typically used during installation configuration to bind a configuration key and default value
   * to a directory path while preserving the existing {@link Node} setup behavior. Use this
   * overload when no custom move error message is needed.
   *
   * @param node owning node used to perform directory setup work.
   * @param installConfig configuration section that stores the directory setting.
   * @param cfgKey configuration key that identifies the directory entry.
   * @param defaultValue default path string used when no value present.
   * @param shortDesc short description key for UI or config text.
   * @param longDesc long description key for UI or config text.
   * @return resolved program directory as a {@link File} for further use.
   * @throws NodeInitException if directory resolution or validation fails.
   */
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

  /**
   * Resolves the program directory from configuration and returns it as a {@link File}.
   *
   * <p>This overload delegates to {@link Node#setupProgramDir(SubConfig, String, String, String,
   * String, String)} and exposes the resulting directory as a {@link File}. The optional move error
   * message allows callers to customize the error text when a directory move fails while preserving
   * the underlying setup semantics. Provide a custom message only when the caller must surface a
   * specific migration hint.
   *
   * @param node owning node used to perform directory setup work.
   * @param installConfig configuration section that stores the directory setting.
   * @param cfgKey configuration key that identifies the directory entry.
   * @param defaultValue default path string used when no value present.
   * @param shortDesc short description key for UI or config text.
   * @param longDesc long description key for UI or config text.
   * @param moveErrMsg optional move error message or {@code null} to use defaults.
   * @return resolved program directory as a {@link File} for further use.
   * @throws NodeInitException if directory resolution or validation fails.
   */
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

  /**
   * Creates archive and healing resources required for client context initialization.
   *
   * <p>This method builds an {@link ArchiveManager} configured with the provided limits and
   * temporary bucket factory, then constructs a {@link SimpleHealingQueue} using an {@link
   * InsertContext} aligned with the legacy defaults. Healing decisions are backed by the node's
   * location and opennet state. The returned resources are not registered automatically; callers
   * retain ownership and are responsible for wiring them into the client context.
   *
   * @param node node providing location and opennet state for healing decisions.
   * @param tempBucketFactory temporary bucket factory used for archive extraction buffers.
   * @param maxArchiveHandlers maximum concurrent archive handlers allowed by the archive manager.
   * @param maxCachedArchiveData cap on cached archive data bytes kept in memory.
   * @param maxArchivedFileSize maximum permitted archived file size, in bytes.
   * @param maxCachedElements maximum number of cached archive elements retained.
   * @param maxRunningHealingInserts upper bound for concurrent healing insert operations.
   * @return resources containing the configured archive manager and healing queue.
   */
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
                InsertContextOptions.builder()
                    .retryLimits(0, 2)
                    .splitfileSegmentLimits(0, 0)
                    .clientOptions(
                        new SimpleEventProducer(), false, Node.FORK_ON_CACHEABLE_DEFAULT, false)
                    .compressorDescriptor(Compressor.DEFAULT_COMPRESSORDESCRIPTOR)
                    .redundancy(0, 0)
                    .compatibility(InsertContext.CompatibilityMode.COMPAT_DEFAULT)
                    .build()),
            RequestStarter.PREFETCH_PRIORITY_CLASS,
            maxRunningHealingInserts,
            new HealingDecisionSupplier(
                () -> node.network().location(), () -> node.network().isOpennetEnabled()));
    return new ClientContextResources(archiveManager, healingQueue);
  }

  /**
   * Creates a high-level client bound to the provided core.
   *
   * <p>The returned {@link HighLevelSimpleClient} shares the core's client context and uses the
   * provided temporary bucket factory and random source. The priority class and flags are passed
   * through unchanged, allowing the caller to control scheduling and path-component behavior. This
   * method always constructs a new instance and performs no caching; callers manage the lifecycle
   * of the returned client.
   *
   * @param core core that provides the shared client context and settings.
   * @param tempBucketFactory temporary bucket factory used by the client.
   * @param random random source used for client-side operations.
   * @param prioClass priority class value used for request scheduling.
   * @param forceDontIgnoreTooManyPathComponents flag controlling path-component handling behavior
   *     during requests.
   * @param realTimeFlag whether the client should run in real-time mode.
   * @return newly constructed high-level client bound to the provided core.
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
   * <p>The calculation starts at {@link FECCodec#MIN_MEMORY_ALLOCATION} and then adds one twentieth
   * of any memory beyond 512 MiB. This mirrors the previous in-core formula, keeping the same
   * effective defaults for legacy behavior. The result is deterministic, does not allocate memory,
   * and depends only on the supplied limit.
   *
   * @param overallMemoryLimit total memory limit in bytes for the JVM.
   * @return default memory cap in bytes for memory-limited jobs.
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
   * <p>This registers the {@code memoryLimitedJobMemoryLimit} configuration key using the provided
   * default and sort order. The associated {@link LongCallback} enforces {@link
   * FECCodec#MIN_MEMORY_ALLOCATION} and updates the shared runner capacity when the value changes.
   * Callers should use the returned sort order when registering later settings to preserve stable
   * UI ordering.
   *
   * @param init initialization helper providing access to node configuration.
   * @param sortOrder current sort order index used for config registration.
   * @param defaultMemoryLimitedJobMemoryLimit default memory cap in bytes when unset.
   * @param core core providing the shared memory-limited job runner.
   * @return next sort order value after registering this setting.
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
            new Option.Meta(
                sortOrder,
                true,
                false,
                "NodeClientCore.memoryLimitedJobMemoryLimit",
                "NodeClientCore.memoryLimitedJobMemoryLimitLong"),
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

  /**
   * Builds a client CHK block from an encoded block and key.
   *
   * <p>This is a convenience wrapper around {@link ClientCHKBlock} construction that preserves the
   * legacy creation path used by {@link NodeClientCore}. Verification is performed during
   * construction, so invalid inputs surface as a checked exception. The returned {@link
   * ClientKeyBlock} can be passed to higher-level client APIs that operate on verified blocks.
   *
   * @param block encoded CHK block data to verify and wrap.
   * @param key client CHK key describing block parameters and verification.
   * @return client key block representing the verified CHK payload.
   * @throws CHKVerifyException if block verification fails for the provided key.
   */
  public static ClientKeyBlock buildClientChkBlock(CHKBlock block, ClientCHK key)
      throws CHKVerifyException {
    return new ClientCHKBlock(block, key);
  }

  /**
   * Builds a client CHK block from raw data and headers.
   *
   * <p>This variant accepts raw payload and header buffers and forwards them to the {@link
   * ClientCHKBlock} constructor along with the supplied key. Verification happens during
   * construction, and invalid inputs result in a checked exception. Use this helper when upstream
   * logic has already split the encoded block into data and header components.
   *
   * @param data raw data bytes of the CHK payload.
   * @param header raw header bytes associated with the CHK payload.
   * @param key client CHK key used to verify and interpret inputs.
   * @return client key block representing the verified CHK payload.
   * @throws CHKVerifyException if verification fails for the provided data and key.
   */
  public static ClientKeyBlock buildClientChkBlock(byte[] data, byte[] header, ClientCHK key)
      throws CHKVerifyException {
    return new ClientCHKBlock(data, header, key, true);
  }

  /**
   * Builds a client SSK block from an encoded block and key.
   *
   * <p>This helper delegates to {@link ClientSSKBlock#construct(SSKBlock, ClientSSK)} to create a
   * verified client key block. It preserves the same construction behavior used by the legacy core,
   * including validation and failure signaling via a checked exception. The returned block is ready
   * for client-side processing and validation-aware flows.
   *
   * @param block encoded SSK block data to verify and wrap.
   * @param key client SSK key describing block parameters and verification.
   * @return client key block representing the verified SSK payload.
   * @throws SSKVerifyException if block verification fails for the provided key.
   */
  public static ClientKeyBlock buildClientSskBlock(SSKBlock block, ClientSSK key)
      throws SSKVerifyException {
    return ClientSSKBlock.construct(block, key);
  }

  /**
   * Builds CHK insert options for the local insert path.
   *
   * <p>This creates the {@link PartiallyReceivedBlock} wrapper and applies the same option
   * configuration previously assembled in {@link NodeClientCore}. The headers and data are used to
   * populate the options and the payload wrapper, while the boolean flags control cache behavior,
   * fork-on-cacheable handling, insertion preference, low-backoff handling, and real-time
   * scheduling. A fresh options instance is returned each time.
   *
   * @param headers encoded block header bytes to associate with the insert.
   * @param data block payload bytes used to populate the insert wrapper.
   * @param canWriteClientCache whether client cache writes are permitted.
   * @param forkOnCacheable whether to fork on cacheable inserts.
   * @param preferInsert whether to prefer insertion to fetch behavior.
   * @param ignoreLowBackoff whether low-backoff limits should be ignored.
   * @param realTimeFlag whether to schedule this insert as real-time.
   * @return insert options configured for local CHK insertion.
   */
  public static NodeRoutingSubsystem.ChkInsertOptions buildChkInsertOptions(
      byte[] headers,
      byte[] data,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean preferInsert,
      boolean ignoreLowBackoff,
      boolean realTimeFlag) {
    PartiallyReceivedBlock prb =
        new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE, data);
    return NodeRoutingSubsystem.ChkInsertOptions.of(headers, prb)
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
   * <p>This is a thin wrapper around {@link Files#delete(java.nio.file.Path)} that propagates any
   * {@link IOException} thrown by the underlying file system operation. It performs no retries or
   * fallback logic, so callers should handle failures explicitly when deletion is optional or when
   * user-facing messaging is required.
   *
   * @param file file to delete; passed directly to {@link Files#delete}.
   * @throws IOException if the underlying delete operation fails.
   */
  public static void deleteFile(File file) throws IOException {
    Files.delete(file.toPath());
  }

  /**
   * Computes the most recent failure timing for routing decisions.
   *
   * <p>Mirrors the originator behavior by decrementing HTL before invoking the routing selector. It
   * performs a selector probe using the same parameters as the in-core path and returns the {@code
   * recentlyFailed} value captured from the selector callback. Callers use the returned value to
   * inform routing backoff decisions without reimplementing the selector call sequence.
   *
   * @param node node providing routing selector and HTL configuration.
   * @param key routing key used to select the closest peers.
   * @param realTime whether to apply real-time scheduling constraints.
   * @return recently failed value reported by the routing selector.
   */
  public static long checkRecentlyFailed(Node node, Key key, boolean realTime) {
    RecentlyFailedReturn result = new RecentlyFailedReturn();
    short origHtl = node.routing().decrementHTL(null, node.maxHTL());
    PeerRoutingSelectionParams params =
        new PeerRoutingSelectionParams(
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
            0L,
            true,
            realTime,
            result,
            false,
            System.currentTimeMillis(),
            node.network().enableNewLoadManagement(realTime));
    node.network().peers().routingSelector().closerPeer(params);
    return result.recentlyFailed();
  }

  /**
   * Creates the startup alert displayed until the node finishes initialization.
   *
   * <p>The supplied title and text values are used verbatim, and the alert is created with error
   * severity to communicate that the node is still initializing. Callers typically register the
   * alert at startup and remove or replace it once initialization completes.
   *
   * @param title localized title shown in the alerts list.
   * @param longText detailed message describing the startup state.
   * @param shortText short message used for condensed alert displays.
   * @return newly constructed user alert for startup status.
   */
  public static UserAlert createStartingUpAlert(String title, String longText, String shortText) {
    return new SimpleUserAlert(true, title, longText, shortText, UserAlert.ERROR);
  }

  /**
   * Registers the core FProxy alerts, including the persistence-broken warning.
   *
   * <p>This registers the provided startup alert and then adds the persistence-broken alert derived
   * from the core's state. It centralizes the alert wiring sequence so the calling code can remain
   * focused on the higher-level initialization flow. It does not remove or replace existing alerts.
   *
   * @param alerts alert manager that receives the registrations.
   * @param core core used to build the persistence-broken alert.
   * @param startingUpAlert startup alert to register first.
   */
  public static void registerFProxyAlerts(
      UserAlertManager alerts, NodeClientCore core, UserAlert startingUpAlert) {
    alerts.register(startingUpAlert);
    alerts.register(createPersistenceBrokenAlert(core));
  }

  /**
   * Registers disk-space related user alerts.
   *
   * <p>This method wires both the disk-space warning and datastore-too-small warning alerts into
   * the provided manager. It does not perform any evaluation itself; the alert instances handle
   * their own validation and message updates once registered. Registration order matches the legacy
   * sequence used in the core.
   *
   * @param alerts alert manager that receives the registrations.
   * @param core core used by the alert implementations to query state.
   */
  public static void registerStorageAlerts(UserAlertManager alerts, NodeClientCore core) {
    alerts.register(new DiskSpaceUserAlert(core));
    alerts.register(new DatastoreTooSmallAlert(core));
  }

  /**
   * Returns a localized string for NodeClientCore settings.
   *
   * <p>This helper prefixes the provided key with {@code "NodeClientCore."} and looks it up using
   * {@link NodeL10n#getBase()}. It is intended for simple string lookups without parameter
   * substitution; callers that need substitutions should get the base bundle directly. It does not
   * perform caching; each call performs a bundle lookup.
   *
   * @param key key suffix appended to the {@code NodeClientCore.} prefix.
   * @return localized string for the composed NodeClientCore key.
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
