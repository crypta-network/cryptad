package network.crypta.node;

import java.io.File;
import java.util.Objects;
import java.util.Random;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.USKManager;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.config.SubConfig;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.DiskSpaceCheckingRandomAccessBufferFactory;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.MaybeEncryptedRandomAccessBufferFactory;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.PooledFileRandomAccessBufferFactory;
import network.crypta.support.io.TempBucketFactory;

/**
 * Centralizes persistence-related wiring for {@link NodeClientCore}.
 *
 * <p>This helper isolates the construction of persistence infrastructure that would otherwise
 * sprawl across the client-core initialization flow. Callers typically construct an instance early
 * in node startup, configure disk-checking factories once storage directories are known, and then
 * use it to build the {@link ClientContext} and FCP server wiring. The instance owns a shared
 * {@link PersistentRequestRoot} so persistent request registration is consistent across the
 * client-layer components it creates.
 *
 * <p>State is initialized in stages: the disk checker and persistent RAF factory are {@code null}
 * until {@link #initDiskChecker(FilenameGenerator, File, long, TempBucketFactory, boolean)} is
 * called. Consumers should treat this class as startup-only; it is not designed for concurrent
 * mutation and expects callers to serialize configuration steps before client activity begins.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Creating and starting a configurable persister for throttle state.
 *   <li>Building persistent random-access buffer factories with optional encryption.
 *   <li>Exposing persistent requests and wiring FCP server state.
 *   <li>Constructing {@link ClientContext} with shared persistent roots.
 * </ul>
 *
 * @see NodeClientCore
 * @see ClientContext
 * @see PersistentRequestRoot
 */
public final class NodeClientPersistence {
  private final ConfigurablePersister persister;
  private final PersistentRequestRoot persistentRoot = new PersistentRequestRoot();
  private DiskSpaceCheckingRandomAccessBufferFactory diskChecker;
  private MaybeEncryptedRandomAccessBufferFactory persistentRafFactory;
  private final int sortOrderAfter;

  /**
   * Creates persistence wiring for client-core startup and configuration.
   *
   * <p>The constructor registers a configurable persister under {@code nodeConfig} and selects a
   * default throttle file path relative to the node run directory. It also tracks the next
   * configuration sort order so callers can continue registering options in a stable order. This
   * constructor performs no disk checker setup; callers must invoke {@link #initDiskChecker} before
   * using persistent factories or building the client context.
   *
   * @param persistable provider of throttle state snapshots for persistence.
   * @param nodeConfig configuration section used to register the throttle file option.
   * @param node node instance providing ticker and run directory settings.
   * @param initialSortOrder starting sort order for configuration registration.
   * @throws NodeInitException if the configured throttle file cannot be created or used.
   */
  public NodeClientPersistence(
      Persistable persistable, SubConfig nodeConfig, Node node, int initialSortOrder)
      throws NodeInitException {
    int sortOrder = initialSortOrder;
    persister =
        new ConfigurablePersister(
            persistable,
            nodeConfig,
            "clientThrottleFile",
            "client-throttle.dat",
            sortOrder++,
            true,
            false,
            "NodeClientCore.fileForClientStats",
            "NodeClientCore.fileForClientStatsLong",
            node.network().ticker(),
            node.getRunDir());
    sortOrderAfter = sortOrder;
  }

  /**
   * Returns the next sort order value after persister registration.
   *
   * <p>This value lets callers continue registering configuration options without overlapping the
   * sort order consumed by the persister option in the constructor. The returned value is stable
   * for the lifetime of the instance.
   *
   * @return the sort order value immediately after the persister option.
   */
  public int getSortOrderAfter() {
    return sortOrderAfter;
  }

  /**
   * Reads the most recently persisted throttle snapshot.
   *
   * <p>This delegates to the underlying {@link ConfigurablePersister} and returns the parsed {@link
   * SimpleFieldSet} if available. When no persisted file exists or the read fails, the return value
   * may be {@code null}. The method performs no mutation and is safe to call repeatedly during
   * startup.
   *
   * @return the persisted throttle field set, or {@code null} when unavailable.
   */
  public SimpleFieldSet readThrottle() {
    return persister.read();
  }

  /**
   * Starts periodic persistence of throttle state.
   *
   * <p>The persister performs an immediate write and schedules future writes on the configured
   * {@link Ticker}. Repeated calls are ignored by the underlying persister, so callers may safely
   * invoke this during startup without tracking whether it has already run.
   */
  public void startThrottle() {
    persister.start();
  }

  /**
   * Initializes disk-space checking and persistent RAF factories.
   *
   * <p>This method wires a {@link DiskSpaceCheckingRandomAccessBufferFactory} backed by a {@link
   * PooledFileRandomAccessBufferFactory} using the provided filename generator and directory. It
   * also creates the {@link MaybeEncryptedRandomAccessBufferFactory} used for persistent temporary
   * buckets. Call this before {@link #getPersistentRafFactory()}, {@link
   * #installDiskChecker(PersistentTempBucketFactory)}, or {@link #createClientContext} to ensure
   * those components can access the initialized factories.
   *
   * @param persistentFilenameGenerator generator for persistent random-access buffer filenames.
   * @param persistentTempDir directory used for persistent temporary file storage.
   * @param minDiskFreeLongTerm minimum free disk space in bytes to preserve.
   * @param tempBucketFactory transient bucket factory used to account for RAM usage.
   * @param encryptPersistentTempBuckets whether new persistent temp buckets should be encrypted.
   */
  public void initDiskChecker(
      FilenameGenerator persistentFilenameGenerator,
      File persistentTempDir,
      long minDiskFreeLongTerm,
      TempBucketFactory tempBucketFactory,
      boolean encryptPersistentTempBuckets) {
    PooledFileRandomAccessBufferFactory raff =
        new PooledFileRandomAccessBufferFactory(persistentFilenameGenerator);
    DiskSpaceCheckingRandomAccessBufferFactory checker =
        new DiskSpaceCheckingRandomAccessBufferFactory(
            raff, persistentTempDir, minDiskFreeLongTerm + tempBucketFactory.getMaxRamUsed());
    diskChecker = checker;
    persistentRafFactory =
        new MaybeEncryptedRandomAccessBufferFactory(checker, encryptPersistentTempBuckets);
  }

  /**
   * Returns the persistent random-access buffer factory.
   *
   * <p>The factory is created by {@link #initDiskChecker} and is required for persistent request
   * workflows. If initialization has not occurred yet, this method throws a {@link
   * NullPointerException} to surface the missing configuration early.
   *
   * @return the initialized persistent RAF factory for future allocations.
   * @throws NullPointerException if {@link #initDiskChecker} has not been called yet.
   */
  public MaybeEncryptedRandomAccessBufferFactory getPersistentRafFactory() {
    return Objects.requireNonNull(persistentRafFactory, "Persistent RAF factory not initialized");
  }

  /**
   * Reports whether the persistent RAF factory has been initialized.
   *
   * <p>This is a convenience check for startup flows that may conditionally enable persistence. It
   * reflects only whether {@link #initDiskChecker} has run; it does not validate any disk
   * permissions or encryption configuration.
   *
   * @return {@code true} when the persistent RAF factory is available.
   */
  public boolean hasPersistentRafFactory() {
    return persistentRafFactory != null;
  }

  /**
   * Enables or disables encryption for newly created persistent RAFs.
   *
   * <p>The toggle affects buffers allocated after the call and delegates to {@link
   * MaybeEncryptedRandomAccessBufferFactory}. Existing buffers remain unchanged. This method
   * requires {@link #initDiskChecker} to have completed.
   *
   * @param enable {@code true} to encrypt future allocations, {@code false} for plaintext.
   * @throws NullPointerException if the persistent RAF factory has not been initialized.
   */
  public void setPersistentRafEncryption(boolean enable) {
    getPersistentRafFactory().setEncryption(enable);
  }

  /**
   * Sets the master secret used for encrypting persistent RAF allocations.
   *
   * <p>The secret is forwarded to the {@link MaybeEncryptedRandomAccessBufferFactory} used for
   * persistent temp storage. The value is applied to future allocations only and does not rewrite
   * already-created buffers. Initialization via {@link #initDiskChecker} is required.
   *
   * @param secret master secret used to encrypt newly allocated buffers.
   * @throws NullPointerException if the persistent RAF factory has not been initialized.
   */
  public void setPersistentRafMasterSecret(MasterSecret secret) {
    getPersistentRafFactory().setMasterSecret(secret);
  }

  /**
   * Installs the disk space checker into a persistent bucket factory.
   *
   * <p>This delegates to {@link PersistentTempBucketFactory#setDiskSpaceChecker} after verifying
   * that the internal checker has been initialized. Call {@link #initDiskChecker} first so the
   * checker reflects the correct directory and reserve limits.
   *
   * @param persistentTempBucketFactory factory that should consult disk-space limits.
   * @throws NullPointerException if the disk checker has not been initialized.
   */
  public void installDiskChecker(PersistentTempBucketFactory persistentTempBucketFactory) {
    persistentTempBucketFactory.setDiskSpaceChecker(requireDiskChecker());
  }

  /**
   * Updates the minimum free-space reserve for persistent allocations.
   *
   * <p>The reserve is enforced by the underlying {@link DiskSpaceCheckingRandomAccessBufferFactory}
   * and is expressed in bytes. This method requires the disk checker to be initialized and will
   * propagate {@link IllegalArgumentException} if a negative reserve is supplied.
   *
   * @param minDiskSpace minimum free disk space, in bytes, to preserve.
   * @throws NullPointerException if the disk checker has not been initialized.
   * @throws IllegalArgumentException if {@code minDiskSpace} is negative.
   */
  public void updateMinDiskSpace(long minDiskSpace) {
    requireDiskChecker().setMinDiskSpace(minDiskSpace);
  }

  /**
   * Creates the FCP server configured for this node and client core.
   *
   * <p>The server is constructed via {@link FCPServer#maybeCreate(Node, NodeClientCore,
   * network.crypta.config.Config, PersistentRequestRoot)} and shares this instance's persistent
   * request root so durable requests can be managed consistently across reconnects. This method
   * performs no side effects beyond the delegation.
   *
   * @param node node instance supplying configuration and shared services.
   * @param core client core used by the FCP server for callbacks.
   * @return the configured FCP server instance from {@code maybeCreate}.
   */
  public FCPServer createFcpServer(Node node, NodeClientCore core) {
    return FCPServer.maybeCreate(node, core, node.getConfig(), persistentRoot);
  }

  /**
   * Returns a snapshot of all currently registered persistent requests.
   *
   * <p>The snapshot is provided by the shared {@link PersistentRequestRoot} and may include global
   * and per-client persistent requests. The returned array is a point-in-time view; subsequent
   * request registrations or removals are not reflected in the array.
   *
   * @return an array of persistent client requests; never {@code null}.
   */
  public ClientRequest[] getPersistentRequests() {
    return persistentRoot.getPersistentRequests();
  }

  /**
   * Builds a fully wired {@link ClientContext} for client-layer operations.
   *
   * <p>This method assembles the context from the supplied schedulers, factories, and defaults,
   * wiring in the persistent request root and disk checker owned by this instance. Callers should
   * invoke {@link #initDiskChecker} first; otherwise a {@link NullPointerException} is thrown to
   * signal the missing persistence wiring. The returned context is a new object and does not mutate
   * any of the provided collaborators beyond normal constructor usage.
   *
   * @param node node instance supplying boot id and configuration references.
   * @param clientLayerPersister persistence runner used to serialize durable client jobs.
   * @param executor priority-aware executor for main client-layer scheduling.
   * @param resources bundle with archive manager and healing queue.
   * @param persistentTempBucketFactory factory for persistent temp buckets and file tracking.
   * @param tempBucketFactory factory for transient temp buckets and in-memory limits.
   * @param uskManager manager for USK coordination and update tracking.
   * @param random strong random source for cryptographic and protocol needs.
   * @param fastWeakRandom fast non-cryptographic random source for jitter.
   * @param ticker scheduler used for time-based client operations.
   * @param memoryLimitedJobRunner runner constraining memory-intensive background tasks.
   * @param tempFilenameGenerator generator for transient temp filenames and ids.
   * @param persistentFilenameGenerator generator for persistent on-disk temp filenames.
   * @param tempRafFactory factory for transient random-access buffers.
   * @param persistentRafFactory factory for persistent random-access buffers, possibly encrypted.
   * @param fileRafTransient factory for transient file-backed random-access buffers.
   * @param compressor compressor implementation for client-side data pipelines.
   * @param storeChecker datastore checker for verification and background checks.
   * @param cryptoSecretTransient transient master secret for this process lifetime.
   * @param init initialization bundle providing toadlets and config.
   * @param defaultFetchContext default fetch context template for persistent requests.
   * @param defaultInsertContext default insert context template for persistent requests.
   * @return newly constructed client context with wired factories and persistent root.
   * @throws NullPointerException if the disk checker has not been initialized.
   */
  public ClientContext createClientContext(
      Node node,
      ClientLayerPersister clientLayerPersister,
      PriorityAwareExecutor executor,
      ClientContextResources resources,
      PersistentTempBucketFactory persistentTempBucketFactory,
      TempBucketFactory tempBucketFactory,
      USKManager uskManager,
      RandomSource random,
      Random fastWeakRandom,
      Ticker ticker,
      MemoryLimitedJobRunner memoryLimitedJobRunner,
      FilenameGenerator tempFilenameGenerator,
      FilenameGenerator persistentFilenameGenerator,
      LockableRandomAccessBufferFactory tempRafFactory,
      MaybeEncryptedRandomAccessBufferFactory persistentRafFactory,
      FileRandomAccessBufferFactory fileRafTransient,
      RealCompressor compressor,
      DatastoreChecker storeChecker,
      MasterSecret cryptoSecretTransient,
      NodeClientCoreInit init,
      FetchContext defaultFetchContext,
      InsertContext defaultInsertContext) {
    DiskSpaceCheckingRandomAccessBufferFactory checker = requireDiskChecker();
    ClientContextRuntime runtime =
        new ClientContextRuntime(
            clientLayerPersister,
            executor,
            memoryLimitedJobRunner,
            ticker,
            random,
            fastWeakRandom,
            cryptoSecretTransient);
    ClientContextStorageFactories storageFactories =
        new ClientContextStorageFactories(
            persistentTempBucketFactory,
            tempBucketFactory,
            persistentTempBucketFactory,
            tempFilenameGenerator,
            persistentFilenameGenerator,
            fileRafTransient,
            checker);
    ClientContextRafFactories rafFactories =
        new ClientContextRafFactories(tempRafFactory, persistentRafFactory);
    ClientContextServices services =
        new ClientContextServices(
            resources, uskManager, compressor, storeChecker, persistentRoot, init.toadlets());
    ClientContextDefaults defaults =
        new ClientContextDefaults(defaultFetchContext, defaultInsertContext, init.config());
    return new ClientContext(
        node.getBootId(), runtime, storageFactories, rafFactories, services, defaults);
  }

  private DiskSpaceCheckingRandomAccessBufferFactory requireDiskChecker() {
    return Objects.requireNonNull(diskChecker, "Persistent disk checker not initialized");
  }
}
