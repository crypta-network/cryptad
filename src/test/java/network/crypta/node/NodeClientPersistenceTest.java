package network.crypta.node;

import java.io.File;
import java.util.Arrays;
import java.util.Random;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.USKManager;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.PersistentRequestClient;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.Config;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.DiskSpaceChecker;
import network.crypta.support.io.DiskSpaceCheckingRandomAccessBufferFactory;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.MaybeEncryptedRandomAccessBufferFactory;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NodeClientPersistenceTest {

  @Test
  void constructor_whenInitialSortOrderProvided_expectIncrementedSortOrderAfter(
      @TempDir File tempDir) throws NodeInitException {
    // Arrange
    Persistable persistable = mock(Persistable.class);
    Ticker ticker = mock(Ticker.class);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    Node node = newNode(ticker, tempDir);

    // Act
    NodeClientPersistence persistence = new NodeClientPersistence(persistable, nodeConfig, node, 7);

    // Assert
    assertEquals(8, persistence.getSortOrderAfter());
    assertFalse(persistence.hasPersistentRafFactory());
  }

  @Test
  void startThrottle_whenInvoked_expectPersisterQueuedNextRun(@TempDir File tempDir)
      throws NodeInitException {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("limit", "42");
    Persistable persistable = mock(Persistable.class);
    when(persistable.persistThrottlesToFieldSet()).thenReturn(fieldSet);
    Ticker ticker = mock(Ticker.class);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    Node node = newNode(ticker, tempDir);
    NodeClientPersistence persistence = new NodeClientPersistence(persistable, nodeConfig, node, 0);

    // Act
    persistence.startThrottle();

    // Assert
    verify(ticker).queueTimedJob(any(Runnable.class), eq(Persister.PERIOD));
  }

  @Test
  void readThrottle_whenThrottlePersisted_expectValue(@TempDir File tempDir)
      throws NodeInitException {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("limit", "42");
    Persistable persistable = mock(Persistable.class);
    when(persistable.persistThrottlesToFieldSet()).thenReturn(fieldSet);
    Ticker ticker = mock(Ticker.class);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    Node node = newNode(ticker, tempDir);
    NodeClientPersistence persistence = new NodeClientPersistence(persistable, nodeConfig, node, 0);

    // Act
    persistence.startThrottle();
    SimpleFieldSet result = persistence.readThrottle();

    // Assert
    assertNotNull(result);
    assertEquals("42", result.get("limit"));
  }

  @Test
  void initDiskChecker_whenCalled_expectPersistentRafFactoryAvailableAndInstalled(
      @TempDir File tempDir) throws NodeInitException {
    // Arrange
    Persistable persistable = mock(Persistable.class);
    Ticker ticker = mock(Ticker.class);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    Node node = newNode(ticker, tempDir);
    NodeClientPersistence persistence = new NodeClientPersistence(persistable, nodeConfig, node, 0);
    FilenameGenerator filenameGenerator = mock(FilenameGenerator.class);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    when(tempBucketFactory.getMaxRamUsed()).thenReturn(128L);
    File persistentTempDir = new File(tempDir, "persistent");
    assertTrue(persistentTempDir.mkdirs() || persistentTempDir.isDirectory());

    // Act
    persistence.initDiskChecker(
        filenameGenerator, persistentTempDir, 1024L, tempBucketFactory, true);
    PersistentTempBucketFactory persistentTempBucketFactory =
        mock(PersistentTempBucketFactory.class);
    persistence.installDiskChecker(persistentTempBucketFactory);

    // Assert
    assertTrue(persistence.hasPersistentRafFactory());
    assertNotNull(persistence.getPersistentRafFactory());
    ArgumentCaptor<DiskSpaceChecker> captor = ArgumentCaptor.forClass(DiskSpaceChecker.class);
    verify(persistentTempBucketFactory).setDiskSpaceChecker(captor.capture());
    assertInstanceOf(DiskSpaceCheckingRandomAccessBufferFactory.class, captor.getValue());
  }

  @Test
  void getPersistentRafFactory_whenNotInitialized_expectNullPointerException(@TempDir File tempDir)
      throws NodeInitException {
    // Arrange
    NodeClientPersistence persistence = newPersistence(tempDir);

    // Act
    NullPointerException ex =
        assertThrows(NullPointerException.class, persistence::getPersistentRafFactory);

    // Assert
    assertEquals("Persistent RAF factory not initialized", ex.getMessage());
  }

  @Test
  void setPersistentRafEncryption_whenNotInitialized_expectNullPointerException(
      @TempDir File tempDir) throws NodeInitException {
    // Arrange
    NodeClientPersistence persistence = newPersistence(tempDir);

    // Act
    NullPointerException ex =
        assertThrows(
            NullPointerException.class, () -> persistence.setPersistentRafEncryption(true));

    // Assert
    assertEquals("Persistent RAF factory not initialized", ex.getMessage());
  }

  @Test
  void setPersistentRafMasterSecret_whenNotInitialized_expectNullPointerException(
      @TempDir File tempDir) throws NodeInitException {
    // Arrange
    NodeClientPersistence persistence = newPersistence(tempDir);

    // Act
    NullPointerException ex =
        assertThrows(
            NullPointerException.class, () -> persistence.setPersistentRafMasterSecret(null));

    // Assert
    assertEquals("Persistent RAF factory not initialized", ex.getMessage());
  }

  @Test
  void installDiskChecker_whenNotInitialized_expectNullPointerException(@TempDir File tempDir)
      throws NodeInitException {
    // Arrange
    NodeClientPersistence persistence = newPersistence(tempDir);
    PersistentTempBucketFactory persistentTempBucketFactory =
        mock(PersistentTempBucketFactory.class);

    // Act
    NullPointerException ex =
        assertThrows(
            NullPointerException.class,
            () -> persistence.installDiskChecker(persistentTempBucketFactory));

    // Assert
    assertEquals("Persistent disk checker not initialized", ex.getMessage());
  }

  @Test
  void updateMinDiskSpace_whenNegative_expectIllegalArgumentException(@TempDir File tempDir)
      throws NodeInitException {
    // Arrange
    NodeClientPersistence persistence = newPersistence(tempDir);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    when(tempBucketFactory.getMaxRamUsed()).thenReturn(0L);
    File persistentTempDir = new File(tempDir, "persistent");
    assertTrue(persistentTempDir.mkdirs() || persistentTempDir.isDirectory());
    persistence.initDiskChecker(
        mock(FilenameGenerator.class), persistentTempDir, 1L, tempBucketFactory, false);

    // Act
    assertThrows(IllegalArgumentException.class, () -> persistence.updateMinDiskSpace(-1L));
  }

  @Test
  void createClientContext_whenDiskCheckerMissing_expectNullPointerException(@TempDir File tempDir)
      throws NodeInitException {
    // Arrange
    NodeClientPersistence persistence = newPersistence(tempDir);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    ClientLayerPersister clientLayerPersister = mock(ClientLayerPersister.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    ClientContextResources resources =
        new ClientContextResources(
            mock(ArchiveManager.class), mock(network.crypta.client.async.HealingQueue.class));
    PersistentTempBucketFactory persistentTempBucketFactory =
        mock(PersistentTempBucketFactory.class);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    USKManager uskManager = mock(USKManager.class);
    RandomSource randomSource = mock(RandomSource.class);
    Random fastWeakRandom = new Random(1234L);
    Ticker ticker = mock(Ticker.class);
    MemoryLimitedJobRunner memoryLimitedJobRunner = mock(MemoryLimitedJobRunner.class);
    FilenameGenerator tempFilenameGenerator = mock(FilenameGenerator.class);
    FilenameGenerator persistentFilenameGenerator = mock(FilenameGenerator.class);
    LockableRandomAccessBufferFactory tempRafFactory =
        mock(LockableRandomAccessBufferFactory.class);
    MaybeEncryptedRandomAccessBufferFactory persistentRafFactory =
        mock(MaybeEncryptedRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRafTransient = mock(FileRandomAccessBufferFactory.class);
    RealCompressor compressor = mock(RealCompressor.class);
    DatastoreChecker storeChecker = mock(DatastoreChecker.class);
    MasterSecret cryptoSecretTransient = new MasterSecret(new byte[64]);
    NodeClientCoreInit init =
        new NodeClientCoreInit(
            mock(Config.class),
            mock(SubConfig.class),
            mock(SubConfig.class),
            mock(SimpleToadletServer.class));
    FetchContext defaultFetchContext = mock(FetchContext.class);
    InsertContext defaultInsertContext = mock(InsertContext.class);

    ClientContextInitParams params =
        new ClientContextInitParams(
            clientLayerPersister,
            executor,
            resources,
            persistentTempBucketFactory,
            tempBucketFactory,
            uskManager,
            randomSource,
            fastWeakRandom,
            ticker,
            memoryLimitedJobRunner,
            tempFilenameGenerator,
            persistentFilenameGenerator,
            tempRafFactory,
            persistentRafFactory,
            fileRafTransient,
            compressor,
            storeChecker,
            cryptoSecretTransient,
            init,
            defaultFetchContext,
            defaultInsertContext);

    // Act
    NullPointerException ex =
        assertThrows(
            NullPointerException.class, () -> persistence.createClientContext(node, params));

    // Assert
    assertEquals("Persistent disk checker not initialized", ex.getMessage());
  }

  @Test
  void createClientContext_whenInitialized_expectContextWiresDependencies(@TempDir File tempDir)
      throws NodeInitException {
    // Arrange
    Ticker ticker = mock(Ticker.class);
    PersistentConfig config = mock(PersistentConfig.class);
    Node node = newNode(ticker, tempDir);
    when(node.getBootId()).thenReturn(123L);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    NodeClientPersistence persistence =
        new NodeClientPersistence(mock(Persistable.class), nodeConfig, node, 0);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    when(tempBucketFactory.getMaxRamUsed()).thenReturn(0L);
    File persistentTempDir = new File(tempDir, "persistent");
    assertTrue(persistentTempDir.mkdirs() || persistentTempDir.isDirectory());
    persistence.initDiskChecker(
        mock(FilenameGenerator.class), persistentTempDir, 1L, tempBucketFactory, false);

    ClientLayerPersister clientLayerPersister = mock(ClientLayerPersister.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    ArchiveManager archiveManager = mock(ArchiveManager.class);
    network.crypta.client.async.HealingQueue healingQueue =
        mock(network.crypta.client.async.HealingQueue.class);
    ClientContextResources resources = new ClientContextResources(archiveManager, healingQueue);
    PersistentTempBucketFactory persistentTempBucketFactory =
        mock(PersistentTempBucketFactory.class);
    USKManager uskManager = mock(USKManager.class);
    RandomSource random = mock(RandomSource.class);
    Random fastWeakRandom = new Random(1234L);
    MemoryLimitedJobRunner memoryLimitedJobRunner = mock(MemoryLimitedJobRunner.class);
    FilenameGenerator tempFilenameGenerator = mock(FilenameGenerator.class);
    FilenameGenerator persistentFilenameGenerator = mock(FilenameGenerator.class);
    LockableRandomAccessBufferFactory tempRafFactory =
        mock(LockableRandomAccessBufferFactory.class);
    MaybeEncryptedRandomAccessBufferFactory persistentRafFactory =
        persistence.getPersistentRafFactory();
    FileRandomAccessBufferFactory fileRafTransient = mock(FileRandomAccessBufferFactory.class);
    RealCompressor compressor = mock(RealCompressor.class);
    DatastoreChecker storeChecker = mock(DatastoreChecker.class);
    MasterSecret cryptoSecretTransient = new MasterSecret(new byte[64]);
    SimpleToadletServer toadlets = mock(SimpleToadletServer.class);
    NodeClientCoreInit init =
        new NodeClientCoreInit(config, mock(SubConfig.class), mock(SubConfig.class), toadlets);
    FetchContext defaultFetchContext = mock(FetchContext.class);
    InsertContext defaultInsertContext = mock(InsertContext.class);

    ClientContextInitParams params =
        new ClientContextInitParams(
            clientLayerPersister,
            executor,
            resources,
            persistentTempBucketFactory,
            tempBucketFactory,
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
            compressor,
            storeChecker,
            cryptoSecretTransient,
            init,
            defaultFetchContext,
            defaultInsertContext);

    // Act
    ClientContext context = persistence.createClientContext(node, params);

    // Assert
    assertAll(
        () -> assertEquals(123L, context.bootID),
        () -> assertSame(archiveManager, context.archiveManager),
        () -> assertSame(persistentTempBucketFactory, context.getPersistentFileTracker()),
        () -> assertSame(tempBucketFactory, context.tempBucketFactory),
        () -> assertSame(tempRafFactory, context.tempRAFFactory),
        () -> assertSame(persistentRafFactory, context.persistentRAFFactory),
        () -> assertSame(healingQueue, context.healingQueue),
        () -> assertSame(uskManager, context.uskManager),
        () -> assertSame(random, context.random),
        () -> assertSame(fastWeakRandom, context.fastWeakRandom),
        () -> assertSame(ticker, context.ticker),
        () -> assertSame(memoryLimitedJobRunner, context.memoryLimitedJobRunner),
        () -> assertSame(tempFilenameGenerator, context.fg),
        () -> assertSame(persistentFilenameGenerator, context.persistentFG),
        () -> assertSame(compressor, context.rc),
        () -> assertSame(storeChecker, context.checker),
        () -> assertSame(cryptoSecretTransient, context.cryptoSecretTransient),
        () -> assertSame(config, context.getConfig()),
        () -> assertSame(executor, context.getMainExecutor()),
        () -> assertSame(fileRafTransient, context.getFileRandomAccessBufferFactory(false)),
        () ->
            assertInstanceOf(
                DiskSpaceCheckingRandomAccessBufferFactory.class,
                context.getFileRandomAccessBufferFactory(true)),
        () -> assertSame(persistentRafFactory, context.getRandomAccessBufferFactory(true)));
  }

  @Test
  void getPersistentRequests_whenRequestResumed_expectIncludesRequest(@TempDir File tempDir)
      throws NodeInitException {
    // Arrange
    Ticker ticker = mock(Ticker.class);
    PersistentConfig config = mock(PersistentConfig.class);
    Node node = newNode(ticker, tempDir);
    when(node.getBootId()).thenReturn(200L);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    NodeClientPersistence persistence =
        new NodeClientPersistence(mock(Persistable.class), nodeConfig, node, 0);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    when(tempBucketFactory.getMaxRamUsed()).thenReturn(0L);
    File persistentTempDir = new File(tempDir, "persistent");
    assertTrue(persistentTempDir.mkdirs() || persistentTempDir.isDirectory());
    persistence.initDiskChecker(
        mock(FilenameGenerator.class), persistentTempDir, 1L, tempBucketFactory, false);

    ClientContextInitParams params =
        new ClientContextInitParams(
            mock(ClientLayerPersister.class),
            mock(PriorityAwareExecutor.class),
            new ClientContextResources(
                mock(ArchiveManager.class), mock(network.crypta.client.async.HealingQueue.class)),
            mock(PersistentTempBucketFactory.class),
            tempBucketFactory,
            mock(USKManager.class),
            mock(RandomSource.class),
            new Random(4321L),
            ticker,
            mock(MemoryLimitedJobRunner.class),
            mock(FilenameGenerator.class),
            mock(FilenameGenerator.class),
            mock(LockableRandomAccessBufferFactory.class),
            persistence.getPersistentRafFactory(),
            mock(FileRandomAccessBufferFactory.class),
            mock(RealCompressor.class),
            mock(DatastoreChecker.class),
            new MasterSecret(new byte[64]),
            new NodeClientCoreInit(
                config,
                mock(SubConfig.class),
                mock(SubConfig.class),
                mock(SimpleToadletServer.class)),
            mock(FetchContext.class),
            mock(InsertContext.class));
    ClientContext context = persistence.createClientContext(node, params);

    PersistentRequestRoot root = context.persistentRoot;
    PersistentRequestClient client = root.registerForeverClient("client", null);
    ClientRequest request = mock(ClientRequest.class);
    when(request.hasFinished()).thenReturn(false);
    when(request.isPersistentForever()).thenReturn(true);
    client.resume(request);

    // Act
    ClientRequest[] requests = persistence.getPersistentRequests();

    // Assert
    assertTrue(Arrays.asList(requests).contains(request));
  }

  @Test
  void createFcpServer_whenCalled_expectDelegatesToMaybeCreate(@TempDir File tempDir)
      throws NodeInitException {
    // Arrange
    Persistable persistable = mock(Persistable.class);
    Ticker ticker = mock(Ticker.class);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    Node node = newNode(ticker, tempDir);
    PersistentConfig config = mock(PersistentConfig.class);
    when(node.getConfig()).thenReturn(config);
    NodeClientPersistence persistence = new NodeClientPersistence(persistable, nodeConfig, node, 0);
    NodeClientCore core = mock(NodeClientCore.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    FCPServer expected = mock(FCPServer.class);

    // Act
    try (MockedStatic<FCPServer> fcpServerMock = mockStatic(FCPServer.class)) {
      fcpServerMock
          .when(
              () ->
                  FCPServer.maybeCreate(
                      eq(node),
                      eq(core),
                      eq(runtimePorts),
                      eq(config),
                      any(PersistentRequestRoot.class)))
          .thenReturn(expected);

      FCPServer result = persistence.createFcpServer(node, core, runtimePorts);

      // Assert
      assertSame(expected, result);
      fcpServerMock.verify(
          () ->
              FCPServer.maybeCreate(
                  eq(node),
                  eq(core),
                  eq(runtimePorts),
                  eq(config),
                  any(PersistentRequestRoot.class)));
    }
  }

  private static SubConfig newNodeConfig(File throttleFile) {
    SubConfig nodeConfig = mock(SubConfig.class);
    when(nodeConfig.getString("clientThrottleFile")).thenReturn(throttleFile.getAbsolutePath());
    return nodeConfig;
  }

  private static Node newNode(Ticker ticker, File runDir) {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(node.network().ticker()).thenReturn(ticker);
    when(node.getRunDir()).thenReturn(runDir);
    return node;
  }

  private static NodeClientPersistence newPersistence(File tempDir) throws NodeInitException {
    Persistable persistable = mock(Persistable.class);
    Ticker ticker = mock(Ticker.class);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    Node node = newNode(ticker, tempDir);
    return new NodeClientPersistence(persistable, nodeConfig, node, 0);
  }
}
