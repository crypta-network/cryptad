package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Random;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.RandomSource;
import network.crypta.node.RequestClient;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@org.mockito.junit.jupiter.MockitoSettings(strictness = org.mockito.quality.Strictness.LENIENT)
class SplitFileInserterTest {

  private BaseClientPutter parent;
  private PutCompletionCallback cb;
  private LockableRandomAccessBuffer originalData;
  private LockableRandomAccessBuffer raf;
  private ClientContext context;

  @BeforeEach
  void setUp() {
    parent = Mockito.mock(BaseClientPutter.class);
    cb = Mockito.mock(PutCompletionCallback.class);
    originalData = Mockito.mock(LockableRandomAccessBuffer.class);
    raf = Mockito.mock(LockableRandomAccessBuffer.class);

    // Persistent runner that executes jobs immediately and inline for determinism.
    // Persistent job runner used by ClientContext
    ClientLayerPersister jobRunner = Mockito.mock(ClientLayerPersister.class);
    doAnswer(
            inv -> {
              PersistentJob job = inv.getArgument(0);
              // Use the context spy below; it will be initialized later in buildContext().
              job.run(context);
              return null;
            })
        .when(jobRunner)
        .queueNormalOrDrop(any(PersistentJob.class));

    context = buildContext(jobRunner);
  }

  private ClientContext buildContext(ClientLayerPersister runner) {
    // Immediate executor for predictable behavior in tests.
    PriorityAwareExecutor immediateExecutor =
        new PriorityAwareExecutor() {
          @Override
          public void execute(Runnable job) {
            job.run();
          }

          @Override
          public void execute(Runnable job, String jobName) {
            job.run();
          }

          @Override
          public void execute(Runnable job, String jobName, boolean fromTicker) {
            job.run();
          }

          @Override
          public int[] waitingThreads() {
            return new int[0];
          }

          @Override
          public int[] runningThreads() {
            return new int[0];
          }

          @Override
          public int getWaitingThreadsCount() {
            return 0;
          }
        };

    Ticker ticker =
        new Ticker() {
          @Override
          public void queueTimedJob(Runnable job, long offset) {
            job.run();
          }

          @Override
          public void queueTimedJob(
              Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
            job.run();
          }

          @Override
          public PriorityAwareExecutor getExecutor() {
            return immediateExecutor;
          }

          @Override
          public void removeQueuedJob(Runnable job) {
            // Intentionally no-op in tests: we run tasks immediately via the
            // inline executor, so nothing is ever queued to remove.
          }

          @Override
          public void queueTimedJobAbsolute(
              Runnable runner2,
              String name,
              long time,
              boolean runOnTickerAnyway,
              boolean noDupes) {
            runner2.run();
          }
        };

    // Many collaborators are not used by SplitFileInserter directly; provide simple mocks.
    var archiveManager = Mockito.mock(network.crypta.client.ArchiveManager.class);
    var ptbf = Mockito.mock(network.crypta.support.io.PersistentTempBucketFactory.class);
    var tbf = Mockito.mock(network.crypta.support.io.TempBucketFactory.class);
    var tracker = Mockito.mock(network.crypta.support.io.PersistentFileTracker.class);
    var hq = Mockito.mock(network.crypta.client.async.HealingQueue.class);
    var uskManager = Mockito.mock(network.crypta.client.async.USKManager.class);
    var strongRandom = Mockito.mock(RandomSource.class);
    var fastWeakRandom = new Random(1234);
    var memLimited = Mockito.mock(network.crypta.support.MemoryLimitedJobRunner.class);
    var fg = Mockito.mock(network.crypta.support.io.FilenameGenerator.class);
    var persistentFG = Mockito.mock(network.crypta.support.io.FilenameGenerator.class);
    var rafFactory = Mockito.mock(LockableRandomAccessBufferFactory.class);
    var persistentRAFFactory = Mockito.mock(LockableRandomAccessBufferFactory.class);
    var fileRAFTransient =
        Mockito.mock(network.crypta.support.io.FileRandomAccessBufferFactory.class);
    var fileRAFPersistent =
        Mockito.mock(network.crypta.support.io.FileRandomAccessBufferFactory.class);
    var rc = Mockito.mock(network.crypta.support.compress.RealCompressor.class);
    var dsChecker = Mockito.mock(network.crypta.client.async.DatastoreChecker.class);
    var persistentRoot = Mockito.mock(network.crypta.clients.fcp.PersistentRequestRoot.class);
    var masterSecret = Mockito.mock(network.crypta.crypt.MasterSecret.class);
    var linkFilterProvider =
        Mockito.mock(network.crypta.client.filter.LinkFilterExceptionProvider.class);
    var fetchCtx = Mockito.mock(network.crypta.client.FetchContext.class);
    var insertCtx =
        new InsertContext(
            InsertContextOptions.builder()
                .retryLimits(0, 0)
                .splitfileSegmentLimits(128, 128)
                .clientOptions(new SimpleEventProducer(), true, false, false)
                .compressorDescriptor(null)
                .redundancy(0, 0)
                .compatibility(CompatibilityMode.COMPAT_CURRENT)
                .build());
    var config = Mockito.mock(network.crypta.config.Config.class);

    ClientContext ctx =
        new ClientContext(
            1L,
            runner,
            immediateExecutor,
            archiveManager,
            ptbf,
            tbf,
            tracker,
            hq,
            uskManager,
            strongRandom,
            fastWeakRandom,
            ticker,
            memLimited,
            fg,
            persistentFG,
            rafFactory,
            persistentRAFFactory,
            fileRAFTransient,
            fileRAFPersistent,
            rc,
            dsChecker,
            persistentRoot,
            masterSecret,
            linkFilterProvider,
            fetchCtx,
            insertCtx,
            config);

    // Spy to stub scheduler access used by SplitFileInserter's constructor.
    ClientContext spyCtx = Mockito.spy(ctx);
    ClientRequestScheduler insertScheduler = Mockito.mock(ClientRequestScheduler.class);
    doReturn(insertScheduler).when(spyCtx).getChkInsertScheduler(Mockito.anyBoolean());
    when(insertScheduler.fetchingKeys())
        .thenReturn(Mockito.mock(network.crypta.node.KeysFetchingLocally.class));
    return spyCtx;
  }

  private InsertContext newInsertContext() {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(0, 0)
            .splitfileSegmentLimits(128, 128)
            .clientOptions(new SimpleEventProducer(), true, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  private SplitFileInserter newInserter(
      boolean persistent,
      boolean realTime,
      InsertContext ctx,
      MockedConstruction<SplitFileInserterStorage> storageConst,
      MockedConstruction<SplitFileInserterSender> senderConst)
      throws InsertException {
    // Provide benign metadata and crypto parameters; constructor is intercepted by mocks.
    ClientMetadata meta = new ClientMetadata();
    byte[] cryptoKey = new byte[0];
    byte[] hashThisLayer = new byte[0];
    HashResult[] hashes = new HashResult[0];

    // Parent defaults
    when(parent.getClient()).thenReturn(Mockito.mock(RequestClient.class));

    // Build the SUT; the mocked construction ensures heavy collaborators are not executed.
    SplitFileInserter.Options opts =
        new SplitFileInserter.Options.Builder()
            .ctx(ctx)
            .context(context)
            .decompressedLength(0L)
            .compressionCodec(COMPRESSOR_TYPE.GZIP)
            .meta(meta)
            .isMetadata(false)
            .archiveType(ARCHIVE_TYPE.TAR)
            .splitfileCryptoAlgorithm((byte) 0)
            .splitfileCryptoKey(cryptoKey)
            .hashThisLayerOnly(hashThisLayer)
            .hashes(hashes)
            .topDontCompress(false)
            .topRequiredBlocks(0)
            .topTotalBlocks(0)
            .origDataSize(0L)
            .origCompressedDataSize(0L)
            .realTime(realTime)
            .token("tok")
            .build();

    SplitFileInserter sfi =
        new SplitFileInserter(persistent, parent, cb, originalData, /* freeData= */ true, opts);

    // Verify constructor-level accounting interactions with parent when storage reports zeros.
    verify(parent).addMustSucceedBlocks(0);
    verify(parent).addRedundantBlocksInsert(0);
    verify(parent, times(1)).notifyClients(context);

    // Ensure we have a sender and storage mocks created.
    assertNotNull(storageConst.constructed());
    assertNotNull(senderConst.constructed());
    return sfi;
  }

  @Test
  void schedule_whenCHKOnlyFalse_expectStartAndSenderScheduled() throws Exception {
    InsertContext ic = newInsertContext();
    ic.setGetCHKOnly(false);

    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {

      SplitFileInserter sfi = newInserter(false, false, ic, storageConst, senderConst);

      SplitFileInserterSender sender = senderConst.constructed().getFirst();

      sfi.schedule(context);

      verify(cb).onBlockSetFinished(sfi, context);
      verify(storageConst.constructed().getFirst()).start();
      verify(sender).clearWakeupTime(context);
      verify(sender).schedule(context);
    }
  }

  @Test
  void schedule_whenCHKOnlyTrue_expectNoSenderScheduling() throws Exception {
    InsertContext ic = newInsertContext();
    ic.setGetCHKOnly(true);

    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {

      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);

      SplitFileInserterSender sender = senderConst.constructed().getFirst();

      sfi.schedule(context);

      verify(cb).onBlockSetFinished(sfi, context);
      verify(storageConst.constructed().getFirst()).start();
      verify(sender, never()).clearWakeupTime(context);
      verify(sender, never()).schedule(context);
    }
  }

  // schedule() currently does not throw checked exceptions; error handling is covered in
  // encodingProgress_whenScheduleThrows_callsStorageFail via a spy.

  @Test
  void cancel_whenCalled_failsStorageWithCancelled() throws Exception {
    InsertContext ic = newInsertContext();
    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {

      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);

      sfi.cancel(context);

      var storage = storageConst.constructed().getFirst();
      Mockito.verify(storage)
          .fail(Mockito.argThat(e -> e.getMode() == InsertExceptionMode.CANCELLED));
    }
  }

  @Test
  void encodingProgress_whenCHKOnlyTrue_doesNothing() throws Exception {
    InsertContext ic = newInsertContext();
    ic.setGetCHKOnly(true);
    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {

      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);
      SplitFileInserterSender sender = senderConst.constructed().getFirst();

      sfi.encodingProgress();

      verify(sender, never()).clearWakeupTime(context);
      verify(sender, never()).schedule(context);
    }
  }

  @Test
  void encodingProgress_whenScheduleThrows_callsStorageFail() throws Exception {
    InsertContext ic = newInsertContext();
    ic.setGetCHKOnly(false);
    InsertException boom = new InsertException(InsertExceptionMode.INTERNAL_ERROR);

    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {

      SplitFileInserter real = newInserter(true, false, ic, storageConst, senderConst);
      SplitFileInserter spy = Mockito.spy(real);
      Mockito.doThrow(boom).when(spy).schedule(any(ClientContext.class));

      spy.encodingProgress();

      verify(storageConst.constructed().getFirst()).fail(boom);
    }
  }

  @Test
  void onHasKeys_whenEarlyEncodeTrue_encodesAndReportsMetadata() throws Exception {
    InsertContext ic = newInsertContext();
    ic.setEarlyEncode(true);

    Metadata md = Mockito.mock(Metadata.class);

    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> {
                  when(mock.getRAF()).thenReturn(raf);
                  when(mock.encodeMetadata()).thenReturn(md);
                });
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {

      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);

      sfi.onHasKeys();

      // queueNormalOrDrop runs inline (see jobRunner stub in setUp),
      // so callbacks must be invoked synchronously.
      verify(cb).onMetadata(md, sfi, context);
      verify(cb, never()).onSuccess(any(), any());
    }
  }

  @Test
  void onHasKeys_whenCHKOnlyTrue_triggersSuccessAndFreesResources() throws Exception {
    InsertContext ic = newInsertContext();
    ic.setGetCHKOnly(true);

    Metadata md = Mockito.mock(Metadata.class);

    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> {
                  when(mock.getRAF()).thenReturn(raf);
                  when(mock.encodeMetadata()).thenReturn(md);
                });
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {

      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);

      sfi.onHasKeys();

      // onHasKeys() -> onSucceeded() runs via jobRunner inline
      verify(cb).onMetadata(md, sfi, context);
      verify(cb).onSuccess(sfi, context);
      verify(raf).close();
      verify(raf).free();
      verify(originalData).close();
      verify(originalData).free();
    }
  }

  @Test
  void onSucceeded_whenNotEarlyEncode_reportsMetadataAndSuccess() throws Exception {
    InsertContext ic = newInsertContext();
    ic.setEarlyEncode(false);
    ic.setGetCHKOnly(false);
    Metadata md = Mockito.mock(Metadata.class);

    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {

      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);

      sfi.onSucceeded(md);

      verify(cb).onMetadata(md, sfi, context);
      verify(cb).onSuccess(sfi, context);
      verify(senderConst.constructed().getFirst()).unregister(context, parent.getPriorityClass());
    }
  }

  @Test
  void onFailed_cleansUpAndCallsFailure() throws Exception {
    InsertContext ic = newInsertContext();
    InsertException ex = new InsertException(InsertExceptionMode.INTERNAL_ERROR);

    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {

      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);

      sfi.onFailed(ex);

      verify(raf).close();
      verify(raf).free();
      verify(originalData).close();
      verify(originalData).free();
      verify(cb).onFailure(ex, sfi, context);
    }
  }

  @Test
  void getLength_returnsStorageLength() throws Exception {
    InsertContext ic = newInsertContext();

    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> {
                  when(mock.getRAF()).thenReturn(raf);
                  // Mockito mocks expose default 0 for fields; getLength() should mirror it.
                });
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {

      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);

      assertEquals(0L, sfi.getLength());
    }
  }

  @Test
  void onInsertedBlock_notifiesParent() throws Exception {
    InsertContext ic = newInsertContext();
    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {
      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);
      sfi.onInsertedBlock();
      verify(parent).completedBlock(false, context);
    }
  }

  @Test
  void onShutdown_delegatesToStorage() throws Exception {
    InsertContext ic = newInsertContext();
    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {
      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);
      sfi.onShutdown(context);
      verify(storageConst.constructed().getFirst()).onShutdown(context);
    }
  }

  @Test
  void clearCooldown_clearsSenderWakeup() throws Exception {
    InsertContext ic = newInsertContext();
    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {
      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);
      SplitFileInserterSender sender = senderConst.constructed().getFirst();
      sfi.clearCooldown();
      verify(sender).clearWakeupTime(context);
    }
  }

  @Test
  void getPriorityClass_delegatesToParent() throws Exception {
    InsertContext ic = newInsertContext();
    when(parent.getPriorityClass()).thenReturn((short) 42);
    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {
      SplitFileInserter sfi = newInserter(true, false, ic, storageConst, senderConst);
      assertEquals(42, sfi.getPriorityClass());
    }
  }

  @Test
  void simpleAccessors_returnConfiguredValues() throws Exception {
    InsertContext ic = newInsertContext();
    try (MockedConstruction<SplitFileInserterStorage> storageConst =
            Mockito.mockConstruction(
                SplitFileInserterStorage.class,
                (mock, ctx) -> when(mock.getRAF()).thenReturn(raf));
        MockedConstruction<SplitFileInserterSender> senderConst =
            Mockito.mockConstruction(SplitFileInserterSender.class)) {
      SplitFileInserter sfi = newInserter(true, true, ic, storageConst, senderConst);
      assertSame(parent, sfi.getParent());
      assertEquals("tok", sfi.getToken());
    }
  }
}
