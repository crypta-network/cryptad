package network.crypta.runtime.endpoints;

import java.io.File;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextResources;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.USKManager;
import network.crypta.client.async.persistence.PersistentRequestCatalog;
import network.crypta.client.async.persistence.PersistentRequestCoordinator;
import network.crypta.client.async.persistence.PersistentRequestHandle;
import network.crypta.client.async.persistence.PersistentRequestRecoveryCodec;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.config.Config;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeInitException;
import network.crypta.runtime.endpoints.fcp.CoreFcpPersistentRequestCatalog;
import network.crypta.runtime.endpoints.fcp.FcpEndpointHandle;
import network.crypta.runtime.endpoints.fcp.FcpPersistentRequestRecoveryCodec;
import network.crypta.runtime.endpoints.fcp.FcpPersistentRequestServices;
import network.crypta.runtime.fcp.PersistentRequestEndpointServices;
import network.crypta.runtime.fcp.PersistentRequestEndpointServicesFactory;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.runtime.persistence.Persistable;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100", "StringConcatToTextBlock"})
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
    NodeClientPersistence persistence =
        new NodeClientPersistence(persistable, nodeConfig, node, 7, newServicesFactory());

    // Assert
    assertEquals(8, persistence.getSortOrderAfter());
    assertFalse(persistence.hasPersistentRafFactory());
  }

  @Test
  void constructor_whenPersistentRequestEndpointServicesFactoryIsNull_expectNullPointerException() {
    // Act
    NullPointerException ex =
        assertThrows(
            NullPointerException.class,
            () ->
                new NodeClientPersistence(
                    mock(Persistable.class), mock(SubConfig.class), mock(Node.class), 0, null));

    // Assert
    assertEquals("persistentRequestEndpointServicesFactory", ex.getMessage());
  }

  @Test
  void constructor_whenFactoryReturnsNullServices_expectNullPointerException() {
    // Act
    NullPointerException ex =
        assertThrows(
            NullPointerException.class,
            () ->
                new NodeClientPersistence(
                    mock(Persistable.class),
                    mock(SubConfig.class),
                    mock(Node.class),
                    0,
                    () -> null));

    // Assert
    assertEquals("persistentRequestEndpointServices", ex.getMessage());
  }

  @Test
  void constructor_whenServicesCoordinatorIsNull_expectNullPointerException() {
    // Arrange
    PersistentRequestEndpointServices services = mock(PersistentRequestEndpointServices.class);
    when(services.coordinator()).thenReturn(null);

    // Act
    NullPointerException ex =
        assertThrows(
            NullPointerException.class,
            () ->
                new NodeClientPersistence(
                    mock(Persistable.class),
                    mock(SubConfig.class),
                    mock(Node.class),
                    0,
                    () -> services));

    // Assert
    assertEquals("persistentRequestCoordinator", ex.getMessage());
  }

  @Test
  void constructor_whenServicesCatalogIsNull_expectNullPointerException() {
    // Arrange
    PersistentRequestEndpointServices services = mock(PersistentRequestEndpointServices.class);
    when(services.coordinator()).thenReturn(mock(PersistentRequestCoordinator.class));
    when(services.catalog()).thenReturn(null);

    // Act
    NullPointerException ex =
        assertThrows(
            NullPointerException.class,
            () ->
                new NodeClientPersistence(
                    mock(Persistable.class),
                    mock(SubConfig.class),
                    mock(Node.class),
                    0,
                    () -> services));

    // Assert
    assertEquals("persistentRequestCatalog", ex.getMessage());
  }

  @Test
  void constructor_whenServicesRecoveryCodecIsNull_expectNullPointerException() {
    // Arrange
    PersistentRequestEndpointServices services = mock(PersistentRequestEndpointServices.class);
    when(services.coordinator()).thenReturn(mock(PersistentRequestCoordinator.class));
    when(services.catalog()).thenReturn(mock(PersistentRequestCatalog.class));
    when(services.recoveryCodec()).thenReturn(null);

    // Act
    NullPointerException ex =
        assertThrows(
            NullPointerException.class,
            () ->
                new NodeClientPersistence(
                    mock(Persistable.class),
                    mock(SubConfig.class),
                    mock(Node.class),
                    0,
                    () -> services));

    // Assert
    assertEquals("persistentRequestRecoveryCodec", ex.getMessage());
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
    NodeClientPersistence persistence =
        new NodeClientPersistence(persistable, nodeConfig, node, 0, newServicesFactory());

    // Act
    persistence.startThrottle();

    // Assert
    verify(ticker).queueTimedJob(any(Runnable.class), eq(TimeUnit.MINUTES.toMillis(15)));
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
    NodeClientPersistence persistence =
        new NodeClientPersistence(persistable, nodeConfig, node, 0, newServicesFactory());

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
    NodeClientPersistence persistence =
        new NodeClientPersistence(persistable, nodeConfig, node, 0, newServicesFactory());
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
            mock(HttpShellContainer.class));
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
        new NodeClientPersistence(
            mock(Persistable.class), nodeConfig, node, 0, newServicesFactory());
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
    HttpShellContainer toadlets = mock(HttpShellContainer.class);
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
        () -> assertSame(fastWeakRandom, context.fastWeakRandomSource),
        () -> assertSame(ticker, context.ticker),
        () -> assertSame(memoryLimitedJobRunner, context.memoryLimitedJobRunner),
        () -> assertSame(tempFilenameGenerator, context.fg),
        () -> assertSame(persistentFilenameGenerator, context.persistentFG),
        () -> assertSame(compressor, context.rc),
        () -> assertSame(storeChecker, context.checker),
        () -> assertSame(cryptoSecretTransient, context.cryptoSecretTransient),
        () -> assertSame(config, context.getConfig()),
        () -> assertSame(executor, context.getMainExecutor()),
        () ->
            assertContextPersistentStorageFactories(
                context, fileRafTransient, persistentRafFactory));
    assertPersistenceAdaptersConfigured(clientLayerPersister);
  }

  @Test
  void createClientContext_whenFactoryInjected_expectUsesInjectedPersistenceServices(
      @TempDir File tempDir) throws NodeInitException {
    // Arrange
    Ticker ticker = mock(Ticker.class);
    PersistentConfig config = mock(PersistentConfig.class);
    Node node = newNode(ticker, tempDir);
    when(node.getBootId()).thenReturn(321L);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    PersistentRequestEndpointServicesFactory servicesFactory =
        mock(PersistentRequestEndpointServicesFactory.class);
    PersistentRequestEndpointServices services = mock(PersistentRequestEndpointServices.class);
    PersistentRequestCoordinator coordinator = mock(PersistentRequestCoordinator.class);
    PersistentRequestCatalog catalog = mock(PersistentRequestCatalog.class);
    PersistentRequestRecoveryCodec recoveryCodec = mock(PersistentRequestRecoveryCodec.class);
    PersistentRequestHandle[] persistentRequests = {mock(PersistentRequestHandle.class)};
    when(servicesFactory.create()).thenReturn(services);
    when(services.coordinator()).thenReturn(coordinator);
    when(services.catalog()).thenReturn(catalog);
    when(services.recoveryCodec()).thenReturn(recoveryCodec);
    when(services.getPersistentRequests()).thenReturn(persistentRequests);
    NodeClientPersistence persistence =
        new NodeClientPersistence(mock(Persistable.class), nodeConfig, node, 0, servicesFactory);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    when(tempBucketFactory.getMaxRamUsed()).thenReturn(0L);
    File persistentTempDir = new File(tempDir, "persistent");
    assertTrue(persistentTempDir.mkdirs() || persistentTempDir.isDirectory());
    persistence.initDiskChecker(
        mock(FilenameGenerator.class), persistentTempDir, 1L, tempBucketFactory, false);
    ClientLayerPersister clientLayerPersister = mock(ClientLayerPersister.class);

    ClientContextInitParams params =
        new ClientContextInitParams(
            clientLayerPersister,
            mock(PriorityAwareExecutor.class),
            new ClientContextResources(
                mock(ArchiveManager.class), mock(network.crypta.client.async.HealingQueue.class)),
            mock(PersistentTempBucketFactory.class),
            tempBucketFactory,
            mock(USKManager.class),
            mock(RandomSource.class),
            new Random(9876L),
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
                mock(HttpShellContainer.class)),
            mock(FetchContext.class),
            mock(InsertContext.class));

    // Act
    ClientContext context = persistence.createClientContext(node, params);

    // Assert
    assertAll(
        () -> assertSame(coordinator, context.persistentRequestCoordinator),
        () -> assertSame(persistentRequests, persistence.getPersistentRequests()));
    verify(servicesFactory).create();
    verify(clientLayerPersister).configurePersistenceAdapters(catalog, recoveryCodec);
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
        new NodeClientPersistence(
            mock(Persistable.class), nodeConfig, node, 0, newServicesFactory());
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
                mock(HttpShellContainer.class)),
            mock(FetchContext.class),
            mock(InsertContext.class));
    ClientContext context = persistence.createClientContext(node, params);

    ClientRequest request = mock(ClientRequest.class);
    when(request.hasFinished()).thenReturn(false);
    when(request.isPersistentForever()).thenReturn(true);
    context.persistentRequestCoordinator.resumePersistentRequest(request, true, "client");

    // Act
    PersistentRequestHandle[] requests = persistence.getPersistentRequests();

    // Assert
    assertTrue(Arrays.asList(requests).contains(request));
  }

  @Test
  void createFcpEndpointHandle_whenFactoryInjected_expectDelegatesToInjectedServices(
      @TempDir File tempDir) throws NodeInitException {
    // Arrange
    Persistable persistable = mock(Persistable.class);
    Ticker ticker = mock(Ticker.class);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    Node node = newNode(ticker, tempDir);
    PersistentRequestEndpointServicesFactory servicesFactory =
        mock(PersistentRequestEndpointServicesFactory.class);
    PersistentRequestEndpointServices services = mock(PersistentRequestEndpointServices.class);
    FcpEndpointHandle expectedHandle = mock(FcpEndpointHandle.class);
    when(servicesFactory.create()).thenReturn(services);
    when(services.coordinator()).thenReturn(mock(PersistentRequestCoordinator.class));
    when(services.catalog()).thenReturn(mock(PersistentRequestCatalog.class));
    when(services.recoveryCodec()).thenReturn(mock(PersistentRequestRecoveryCodec.class));
    NodeClientPersistence persistence =
        new NodeClientPersistence(persistable, nodeConfig, node, 0, servicesFactory);
    NodeClientCore core = mock(NodeClientCore.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    when(services.createFcpEndpointHandle(node, core, runtimePorts)).thenReturn(expectedHandle);

    // Act
    FcpEndpointHandle result = persistence.createFcpEndpointHandle(node, core, runtimePorts);

    // Assert
    assertSame(expectedHandle, result);
    verify(services).createFcpEndpointHandle(node, core, runtimePorts);
  }

  private static SubConfig newNodeConfig(File throttleFile) {
    SubConfig nodeConfig = mock(SubConfig.class);
    when(nodeConfig.getString("clientThrottleFile")).thenReturn(throttleFile.getAbsolutePath());
    return nodeConfig;
  }

  private static void assertContextPersistentStorageFactories(
      ClientContext context,
      FileRandomAccessBufferFactory fileRafTransient,
      MaybeEncryptedRandomAccessBufferFactory persistentRafFactory) {
    assertSame(fileRafTransient, context.getFileRandomAccessBufferFactory(false));
    assertInstanceOf(
        DiskSpaceCheckingRandomAccessBufferFactory.class,
        context.getFileRandomAccessBufferFactory(true));
    assertSame(persistentRafFactory, context.getRandomAccessBufferFactory(true));
  }

  private static void assertPersistenceAdaptersConfigured(
      ClientLayerPersister clientLayerPersister) {
    ArgumentCaptor<PersistentRequestCatalog> catalogCaptor =
        ArgumentCaptor.forClass(PersistentRequestCatalog.class);
    ArgumentCaptor<PersistentRequestRecoveryCodec> recoveryCodecCaptor =
        ArgumentCaptor.forClass(PersistentRequestRecoveryCodec.class);
    verify(clientLayerPersister)
        .configurePersistenceAdapters(catalogCaptor.capture(), recoveryCodecCaptor.capture());
    assertInstanceOf(CoreFcpPersistentRequestCatalog.class, catalogCaptor.getValue());
    assertInstanceOf(FcpPersistentRequestRecoveryCodec.class, recoveryCodecCaptor.getValue());
  }

  private static Node newNode(Ticker ticker, File runDir) {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(node.network().ticker()).thenReturn(ticker);
    when(node.getRunDir()).thenReturn(runDir);
    return node;
  }

  private static PersistentRequestEndpointServicesFactory newServicesFactory() {
    return FcpPersistentRequestServices::new;
  }

  private static NodeClientPersistence newPersistence(File tempDir) throws NodeInitException {
    Persistable persistable = mock(Persistable.class);
    Ticker ticker = mock(Ticker.class);
    SubConfig nodeConfig = newNodeConfig(new File(tempDir, "client-throttle.dat"));
    Node node = newNode(ticker, tempDir);
    return new NodeClientPersistence(persistable, nodeConfig, node, 0, newServicesFactory());
  }
}
