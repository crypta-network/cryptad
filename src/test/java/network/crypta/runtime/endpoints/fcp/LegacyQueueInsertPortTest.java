package network.crypta.runtime.endpoints.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
import network.crypta.client.Metadata;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextResources;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.client.async.ClientLayerPersister;
import network.crypta.client.async.DatastoreChecker;
import network.crypta.client.async.HealingQueue;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.TooManyFilesInsertException;
import network.crypta.client.async.USKManager;
import network.crypta.client.async.persistence.PersistentRequestCoordinator;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.ClientPut;
import network.crypta.clients.fcp.ClientRequest;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.IdentifierCollisionException;
import network.crypta.clients.fcp.NotAllowedException;
import network.crypta.clients.fcp.PersistentRequestClient;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.endpoints.ClientEndpoints;
import network.crypta.runtime.spi.QueueBrowserUploadInsertRequest;
import network.crypta.runtime.spi.QueueInsertFailureReason;
import network.crypta.runtime.spi.QueueInsertOptions;
import network.crypta.runtime.spi.QueueInsertOutcome;
import network.crypta.runtime.spi.QueueInsertRejectedException;
import network.crypta.runtime.spi.QueueLocalDirectoryInsertRequest;
import network.crypta.runtime.spi.QueueLocalFileInsertRequest;
import network.crypta.runtime.spi.QueueUploadedFile;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class LegacyQueueInsertPortTest {

  @Mock private NodeClientCore core;
  @Mock private ClientEndpoints endpoints;
  @Mock private FCPServer fcp;
  @Mock private ClientLayerPersister jobRunner;
  @Mock private PersistentTempBucketFactory persistentTempBucketFactory;
  @Mock private RuntimePorts runtimePorts;
  @Mock private TransferAccessPort transferAccessPort;
  @Mock private PriorityAwareExecutor executor;

  @TempDir Path tempDir;

  private LegacyQueueInsertPort port;

  @BeforeEach
  void setUp() throws Exception {
    PersistentRequestClient persistentClient = mock(PersistentRequestClient.class);
    when(core.getEndpoints()).thenReturn(endpoints);
    when(endpoints.getFcpEndpoint()).thenReturn(FcpEndpointHandles.wrap(fcp));
    when(core.getClientLayerPersister()).thenReturn(jobRunner);
    when(core.getPersistentTempBucketFactory()).thenReturn(persistentTempBucketFactory);
    when(core.getRuntimePorts()).thenReturn(runtimePorts);
    when(runtimePorts.transferAccess()).thenReturn(transferAccessPort);
    when(fcp.getGlobalForeverClient()).thenReturn(persistentClient);
    when(transferAccessPort.allowUploadFrom(any(File.class))).thenReturn(true);
    when(persistentTempBucketFactory.makeBucket(anyLong())).thenAnswer(_ -> new ArrayBucket());
    when(core.getClientContext()).thenReturn(createClientContext());
    doAnswer(
            invocation -> {
              PersistentJob job = invocation.getArgument(0);
              job.run(null);
              return null;
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());
    doNothing().when(fcp).startBlocking(any(ClientRequest.class));

    port = new LegacyQueueInsertPort(core);
  }

  @Test
  void enqueueBrowserUploadInsert_whenCalled_resolvesFcpLazilyAndReturnsStarted() throws Exception {
    LegacyQueueInsertPort spyPort = spy(port);
    ClientPut clientPut = mock(ClientPut.class);
    AtomicBoolean uploadCopyCompleted = new AtomicBoolean();
    AtomicReference<Boolean> copiedBeforeQueue = new AtomicReference<>();
    AtomicReference<Boolean> checkpointRequested = new AtomicReference<>();
    doAnswer(
            invocation -> {
              copiedBeforeQueue.set(uploadCopyCompleted.get());
              PersistentJob job = invocation.getArgument(0);
              checkpointRequested.set(job.run(null));
              return null;
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());
    QueueUploadedFile upload = upload(() -> uploadCopyCompleted.set(true));
    doReturn(clientPut).when(spyPort).createBrowserUploadClientPut(any(), any(), any());
    QueueBrowserUploadInsertRequest request =
        new QueueBrowserUploadInsertRequest(
            "CHK@", "upload-1", upload, options(true, defaultCompatibilityMode()), "hello.txt");

    verifyNoInteractions(endpoints, fcp);

    QueueInsertOutcome outcome = spyPort.enqueueBrowserUploadInsert(request);

    assertEquals(QueueInsertOutcome.STARTED, outcome);
    assertTrue(copiedBeforeQueue.get());
    assertTrue(checkpointRequested.get());
    verify(endpoints).getFcpEndpoint();
    verify(fcp).startBlocking(any(ClientRequest.class));
  }

  @Test
  void enqueueBrowserUploadInsert_whenIdentifierCollision_returnsIdentifierCollision()
      throws Exception {
    LegacyQueueInsertPort spyPort = spy(port);
    ClientPut clientPut = mock(ClientPut.class);
    doReturn(clientPut).when(spyPort).createBrowserUploadClientPut(any(), any(), any());
    doThrow(new IdentifierCollisionException()).when(fcp).startBlocking(any(ClientRequest.class));

    QueueInsertOutcome outcome =
        spyPort.enqueueBrowserUploadInsert(
            new QueueBrowserUploadInsertRequest(
                "CHK@",
                "upload-1",
                upload(),
                options(true, defaultCompatibilityMode()),
                "hello.txt"));

    assertEquals(QueueInsertOutcome.IDENTIFIER_COLLISION, outcome);
  }

  @Test
  void enqueueBrowserUploadInsert_whenMetadataUnresolved_returnsMetadataUnresolved()
      throws Exception {
    LegacyQueueInsertPort spyPort = spy(port);
    doThrow(new MetadataUnresolvedException(new Metadata[0], "unresolved"))
        .when(spyPort)
        .createBrowserUploadClientPut(any(), any(), any());

    QueueInsertOutcome outcome =
        spyPort.enqueueBrowserUploadInsert(
            new QueueBrowserUploadInsertRequest(
                "CHK@",
                "upload-1",
                upload(),
                options(true, defaultCompatibilityMode()),
                "hello.txt"));

    assertEquals(QueueInsertOutcome.METADATA_UNRESOLVED, outcome);
  }

  @Test
  void enqueueLocalFileInsert_whenAccessDenied_translatesToAccessDeniedRejection()
      throws Exception {
    LegacyQueueInsertPort spyPort = spy(port);
    AtomicReference<Boolean> checkpointRequested = new AtomicReference<>();
    doAnswer(
            invocation -> {
              PersistentJob job = invocation.getArgument(0);
              checkpointRequested.set(job.run(null));
              return null;
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());
    doThrow(new NotAllowedException()).when(spyPort).createLocalFileClientPut(any(), any(), any());
    Path file = Files.writeString(tempDir.resolve("upload.txt"), "hello");

    QueueInsertRejectedException thrown =
        assertThrows(
            QueueInsertRejectedException.class,
            () ->
                spyPort.enqueueLocalFileInsert(
                    new QueueLocalFileInsertRequest(
                        file.toFile(),
                        "CHK@",
                        "upload-1",
                        "text/plain",
                        options(false, defaultCompatibilityMode()),
                        file.getFileName().toString())));

    assertEquals(QueueInsertFailureReason.ACCESS_DENIED, thrown.reason());
    assertFalse(checkpointRequested.get());
  }

  @Test
  void enqueueLocalFileInsert_whenSourceMissing_translatesToSourceNotFoundRejection()
      throws Exception {
    LegacyQueueInsertPort spyPort = spy(port);
    doThrow(new java.io.FileNotFoundException())
        .when(spyPort)
        .createLocalFileClientPut(any(), any(), any());
    File missingFile = tempDir.resolve("missing.txt").toFile();

    QueueInsertRejectedException thrown =
        assertThrows(
            QueueInsertRejectedException.class,
            () ->
                spyPort.enqueueLocalFileInsert(
                    new QueueLocalFileInsertRequest(
                        missingFile,
                        "CHK@",
                        "upload-1",
                        "text/plain",
                        options(false, defaultCompatibilityMode()),
                        missingFile.getName())));

    assertEquals(QueueInsertFailureReason.SOURCE_NOT_FOUND, thrown.reason());
  }

  @Test
  void enqueueLocalDirectoryInsert_whenTooManyFiles_translatesToTooManyFilesRejection()
      throws Exception {
    LegacyQueueInsertPort spyPort = spy(port);
    doThrow(new TooManyFilesInsertException()).when(spyPort).createLocalDirectoryPut(any(), any());
    Path dir = Files.createDirectories(tempDir.resolve("site"));

    QueueInsertRejectedException thrown =
        assertThrows(
            QueueInsertRejectedException.class,
            () ->
                spyPort.enqueueLocalDirectoryInsert(
                    new QueueLocalDirectoryInsertRequest(
                        dir.toFile(),
                        "CHK@",
                        "upload-1",
                        options(false, defaultCompatibilityMode()))));

    assertEquals(QueueInsertFailureReason.TOO_MANY_FILES, thrown.reason());
  }

  @Test
  void enqueueBrowserUploadInsert_whenPersistenceDisabled_translatesToQueueUnavailable()
      throws Exception {
    RandomAccessBucket copiedBucket = mock(RandomAccessBucket.class);
    when(copiedBucket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(persistentTempBucketFactory.makeBucket(anyLong())).thenReturn(copiedBucket);
    PersistenceDisabledException cause = new PersistenceDisabledException();
    doThrow(cause).when(jobRunner).queue(any(PersistentJob.class), anyInt());

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () ->
                port.enqueueBrowserUploadInsert(
                    new QueueBrowserUploadInsertRequest(
                        "CHK@",
                        "upload-1",
                        upload(),
                        options(true, defaultCompatibilityMode()),
                        "hello.txt")));

    assertSame(cause, thrown.getCause());
    verify(copiedBucket).free();
  }

  @Test
  void enqueueBrowserUploadInsert_whenFcpServerMissing_translatesToQueueUnavailable()
      throws Exception {
    RandomAccessBucket copiedBucket = mock(RandomAccessBucket.class);
    when(copiedBucket.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(persistentTempBucketFactory.makeBucket(anyLong())).thenReturn(copiedBucket);
    when(endpoints.getFcpEndpoint()).thenReturn(null);

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () ->
                port.enqueueBrowserUploadInsert(
                    new QueueBrowserUploadInsertRequest(
                        "CHK@",
                        "upload-1",
                        upload(),
                        options(true, defaultCompatibilityMode()),
                        "hello.txt")));

    assertEquals("Persistent request queue unavailable", thrown.getMessage());
    verify(copiedBucket).free();
  }

  private QueueUploadedFile upload() {
    return upload(() -> {});
  }

  private QueueUploadedFile upload(Runnable onClose) {
    byte[] bytes = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    return new QueueUploadedFile(
        "hello.txt",
        "text/plain",
        bytes.length,
        () ->
            new ByteArrayInputStream(bytes) {
              @Override
              public void close() {
                onClose.run();
              }
            });
  }

  private String defaultCompatibilityMode() {
    return InsertContext.CompatibilityMode.COMPAT_DEFAULT.intern().name();
  }

  private QueueInsertOptions options(boolean compress, String compatibilityMode) {
    return new QueueInsertOptions(compress, compatibilityMode, null);
  }

  private ClientContext createClientContext() {
    ArchiveManager archiveManager = org.mockito.Mockito.mock(ArchiveManager.class);
    PersistentTempBucketFactory ptbf = org.mockito.Mockito.mock(PersistentTempBucketFactory.class);
    TempBucketFactory tbf = org.mockito.Mockito.mock(TempBucketFactory.class);
    PersistentFileTracker tracker = org.mockito.Mockito.mock(PersistentFileTracker.class);
    HealingQueue hq = org.mockito.Mockito.mock(HealingQueue.class);
    USKManager uskManager = org.mockito.Mockito.mock(USKManager.class);
    RandomSource strongRandom = org.mockito.Mockito.mock(RandomSource.class);
    Ticker ticker = org.mockito.Mockito.mock(Ticker.class);
    MemoryLimitedJobRunner memoryLimitedJobRunner =
        org.mockito.Mockito.mock(MemoryLimitedJobRunner.class);
    FilenameGenerator fg = org.mockito.Mockito.mock(FilenameGenerator.class);
    LockableRandomAccessBufferFactory rafFactory =
        org.mockito.Mockito.mock(LockableRandomAccessBufferFactory.class);
    LockableRandomAccessBufferFactory persistentRAFFactory =
        org.mockito.Mockito.mock(LockableRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRAFTransient =
        org.mockito.Mockito.mock(FileRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRAFPersistent =
        org.mockito.Mockito.mock(FileRandomAccessBufferFactory.class);
    RealCompressor rc = org.mockito.Mockito.mock(RealCompressor.class);
    DatastoreChecker checker = org.mockito.Mockito.mock(DatastoreChecker.class);
    PersistentRequestCoordinator clientContextPersistentRequestCoordinator =
        org.mockito.Mockito.mock(PersistentRequestCoordinator.class);
    MasterSecret masterSecret = org.mockito.Mockito.mock(MasterSecret.class);
    LinkFilterExceptionProvider linkFilterExceptionProvider =
        org.mockito.Mockito.mock(LinkFilterExceptionProvider.class);
    FetchContext fetchContext = org.mockito.Mockito.mock(FetchContext.class);
    InsertContext insertContext = org.mockito.Mockito.mock(InsertContext.class);
    Config config = org.mockito.Mockito.mock(Config.class);

    return new ClientContext(
        1L,
        new ClientContextRuntime(
            jobRunner,
            executor,
            memoryLimitedJobRunner,
            ticker,
            strongRandom,
            new Random(123),
            masterSecret),
        new ClientContextStorageFactories(
            ptbf, tbf, tracker, fg, fg, fileRAFTransient, fileRAFPersistent),
        new ClientContextRafFactories(rafFactory, persistentRAFFactory),
        new ClientContextServices(
            new ClientContextResources(archiveManager, hq),
            uskManager,
            rc,
            checker,
            clientContextPersistentRequestCoordinator,
            linkFilterExceptionProvider),
        new ClientContextDefaults(fetchContext, insertContext, config));
  }
}
