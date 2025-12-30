package network.crypta.node;

import java.io.File;
import java.util.Objects;
import java.util.Random;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
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

/** Encapsulates persistence wiring for {@link NodeClientCore} to keep dependencies localized. */
public final class NodeClientPersistence {
  private final ConfigurablePersister persister;
  private final PersistentRequestRoot persistentRoot = new PersistentRequestRoot();
  private DiskSpaceCheckingRandomAccessBufferFactory diskChecker;
  private MaybeEncryptedRandomAccessBufferFactory persistentRafFactory;
  private final int sortOrderAfter;

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
            node.getTicker(),
            node.getRunDir());
    sortOrderAfter = sortOrder;
  }

  public int getSortOrderAfter() {
    return sortOrderAfter;
  }

  public SimpleFieldSet readThrottle() {
    return persister.read();
  }

  public void startThrottle() {
    persister.start();
  }

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

  public MaybeEncryptedRandomAccessBufferFactory getPersistentRafFactory() {
    return Objects.requireNonNull(persistentRafFactory, "Persistent RAF factory not initialized");
  }

  public boolean hasPersistentRafFactory() {
    return persistentRafFactory != null;
  }

  public void setPersistentRafEncryption(boolean enable) {
    getPersistentRafFactory().setEncryption(enable);
  }

  public void setPersistentRafMasterSecret(MasterSecret secret) {
    getPersistentRafFactory().setMasterSecret(secret);
  }

  public void installDiskChecker(PersistentTempBucketFactory persistentTempBucketFactory) {
    persistentTempBucketFactory.setDiskSpaceChecker(requireDiskChecker());
  }

  public void updateMinDiskSpace(long minDiskSpace) {
    requireDiskChecker().setMinDiskSpace(minDiskSpace);
  }

  public FCPServer createFcpServer(Node node, NodeClientCore core) {
    return FCPServer.maybeCreate(node, core, node.getConfig(), persistentRoot);
  }

  public ClientRequest[] getPersistentRequests() {
    return persistentRoot.getPersistentRequests();
  }

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
    return new ClientContext(
        node.getBootId(),
        clientLayerPersister,
        executor,
        resources.getArchiveManager(),
        persistentTempBucketFactory,
        tempBucketFactory,
        persistentTempBucketFactory,
        resources.getHealingQueue(),
        uskManager,
        random,
        fastWeakRandom,
        ticker,
        memoryLimitedJobRunner,
        tempFilenameGenerator,
        persistentFilenameGenerator,
        tempRafFactory,
        persistentRafFactory,
        fileRafTransient,
        checker,
        compressor,
        storeChecker,
        persistentRoot,
        cryptoSecretTransient,
        init.getToadlets(),
        defaultFetchContext,
        defaultInsertContext,
        init.getConfig());
  }

  private DiskSpaceCheckingRandomAccessBufferFactory requireDiskChecker() {
    return Objects.requireNonNull(diskChecker, "Persistent disk checker not initialized");
  }
}
