package network.crypta.clients.fcp.bridge;

import java.util.Random;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext;
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
import network.crypta.client.async.PersistentJob;
import network.crypta.client.async.USKManager;
import network.crypta.client.async.persistence.PersistentRequestCoordinator;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.FcpPersistentJob;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.node.NodeClientCore;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class CoreFcpServerRuntimeSupportTest {

  @Mock private NodeClientCore core;
  @Mock private ClientLayerPersister jobRunner;
  @Mock private TempBucketFactory tempBucketFactory;
  @Mock private PersistentTempBucketFactory persistentTempBucketFactory;
  @Mock private RandomSource randomSource;

  @Test
  void constructor_whenCoreNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new CoreFcpServerRuntimeSupport(null));
  }

  @Test
  void persistentRequestRuntimeContext_whenQueried_returnsCoreClientContext() {
    ClientContext clientContext = createClientContext(jobRunner);
    when(core.getClientContext()).thenReturn(clientContext);

    CoreFcpServerRuntimeSupport support = new CoreFcpServerRuntimeSupport(core);

    assertSame(clientContext, support.persistentRequestRuntimeContext());
  }

  @Test
  void queuePersistentJob_whenCalled_delegatesToCoreJobRunnerAndPreservesLabel() throws Exception {
    ClientContext clientContext = createClientContext(jobRunner);
    when(core.getClientContext()).thenReturn(clientContext);

    CoreFcpServerRuntimeSupport support = new CoreFcpServerRuntimeSupport(core);
    FcpPersistentJob persistentJob =
        new FcpPersistentJob() {
          @Override
          public boolean run(PersistentRequestRuntimeContext context) {
            assertSame(clientContext, context);
            return true;
          }

          @Override
          public String toString() {
            return "FCP restartBlocking";
          }
        };

    support.queuePersistentJob(persistentJob, 123);

    ArgumentCaptor<PersistentJob> jobCaptor = ArgumentCaptor.forClass(PersistentJob.class);
    verify(jobRunner).queue(jobCaptor.capture(), eq(123));
    assertEquals("FCP restartBlocking", jobCaptor.getValue().toString());
    assertTrue(jobCaptor.getValue().run(clientContext));
  }

  @Test
  void setCheckpointASAP_whenCalled_delegatesToCoreJobRunner() {
    ClientContext clientContext = createClientContext(jobRunner);
    when(core.getClientContext()).thenReturn(clientContext);

    CoreFcpServerRuntimeSupport support = new CoreFcpServerRuntimeSupport(core);

    support.setCheckpointASAP();

    verify(jobRunner).setCheckpointASAP();
  }

  @Test
  void persistenceAndBucketFactories_whenQueried_delegateToCore() {
    when(core.killedDatabase()).thenReturn(true);
    when(core.getTempBucketFactory()).thenReturn(tempBucketFactory);
    when(core.getPersistentTempBucketFactory()).thenReturn(persistentTempBucketFactory);

    CoreFcpServerRuntimeSupport support = new CoreFcpServerRuntimeSupport(core);

    assertTrue(support.persistenceDisabled());
    assertSame(tempBucketFactory, support.tempBucketFactory());
    assertSame(persistentTempBucketFactory, support.persistentTempBucketFactory());
  }

  @Test
  void fillSecureRandom_whenCalled_delegatesToCoreRandomSource() {
    when(core.getRandom()).thenReturn(randomSource);
    CoreFcpServerRuntimeSupport support = new CoreFcpServerRuntimeSupport(core);
    byte[] bytes = new byte[8];

    support.fillSecureRandom(bytes);

    verify(randomSource).nextBytes(bytes);
  }

  private static ClientContext createClientContext(ClientLayerPersister jobRunner) {
    ArchiveManager archiveManager = mock(ArchiveManager.class);
    PersistentTempBucketFactory persistentBucketFactory = mock(PersistentTempBucketFactory.class);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    PersistentFileTracker persistentFileTracker = mock(PersistentFileTracker.class);
    FilenameGenerator filenameGenerator = mock(FilenameGenerator.class);
    FilenameGenerator persistentFilenameGenerator = mock(FilenameGenerator.class);
    FileRandomAccessBufferFactory fileRAFTransient = mock(FileRandomAccessBufferFactory.class);
    FileRandomAccessBufferFactory fileRAFPersistent = mock(FileRandomAccessBufferFactory.class);
    LockableRandomAccessBufferFactory tempRAFFactory =
        mock(LockableRandomAccessBufferFactory.class);
    LockableRandomAccessBufferFactory persistentRAFFactory =
        mock(LockableRandomAccessBufferFactory.class);
    PriorityAwareExecutor mainExecutor = mock(PriorityAwareExecutor.class);
    MemoryLimitedJobRunner memoryLimitedJobRunner = mock(MemoryLimitedJobRunner.class);
    Ticker ticker = mock(Ticker.class);
    RandomSource strongRandom = mock(RandomSource.class);
    MasterSecret masterSecret = mock(MasterSecret.class);
    PersistentRequestCoordinator persistentRequestCoordinator =
        mock(PersistentRequestCoordinator.class);
    RealCompressor compressor = mock(RealCompressor.class);
    DatastoreChecker checker = mock(DatastoreChecker.class);
    LinkFilterExceptionProvider linkFilterExceptionProvider =
        mock(LinkFilterExceptionProvider.class);
    FetchContext fetchContext = mock(FetchContext.class);
    InsertContext insertContext = mock(InsertContext.class);
    Config config = mock(Config.class);
    HealingQueue healingQueue = mock(HealingQueue.class);
    USKManager uskManager = mock(USKManager.class);

    return new ClientContext(
        1L,
        new ClientContextRuntime(
            jobRunner,
            mainExecutor,
            memoryLimitedJobRunner,
            ticker,
            strongRandom,
            new Random(123),
            masterSecret),
        new ClientContextStorageFactories(
            persistentBucketFactory,
            tempBucketFactory,
            persistentFileTracker,
            filenameGenerator,
            persistentFilenameGenerator,
            fileRAFTransient,
            fileRAFPersistent),
        new ClientContextRafFactories(tempRAFFactory, persistentRAFFactory),
        new ClientContextServices(
            new ClientContextResources(archiveManager, healingQueue),
            uskManager,
            compressor,
            checker,
            persistentRequestCoordinator,
            linkFilterExceptionProvider),
        new ClientContextDefaults(fetchContext, insertContext, config));
  }
}
