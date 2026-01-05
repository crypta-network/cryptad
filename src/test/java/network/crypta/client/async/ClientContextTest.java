package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Random;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.node.ClientContextResources;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.DummyJobRunner;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientContextTest {

  private static final long BOOT_ID = 42L;

  private ClientContext ctx;

  // Core collaborators (mostly mocked)
  private PersistentTempBucketFactory persistentTempBucketFactory;
  private TempBucketFactory tempBucketFactory;
  private PriorityAwareExecutor mainExecutor;
  private Ticker ticker;
  private LockableRandomAccessBufferFactory persistentRAF;
  private FileRandomAccessBufferFactory fileRAFTransient;
  private FileRandomAccessBufferFactory fileRAFPersistent;
  private FetchContext defaultFetchCtx;
  private InsertContext defaultInsertCtx;
  private FakeJobRunner jobRunner;

  @BeforeEach
  void setUp() {
    // Mocks or lightweight fakes for collaborators
    persistentTempBucketFactory = mock(PersistentTempBucketFactory.class);
    tempBucketFactory = mock(TempBucketFactory.class);
    PersistentFileTracker persistentFileTracker = mock(PersistentFileTracker.class);
    mainExecutor = mock(PriorityAwareExecutor.class);
    MemoryLimitedJobRunner memoryLimitedJobRunner = mock(MemoryLimitedJobRunner.class);
    RandomSource strongRandom = mock(RandomSource.class);
    Random fastWeakRandom = new Random(1234);
    ticker = new FakeTicker(mainExecutor);
    FilenameGenerator fg = mock(FilenameGenerator.class);
    FilenameGenerator persistentFG = mock(FilenameGenerator.class);
    LockableRandomAccessBufferFactory tempRAF = mock(LockableRandomAccessBufferFactory.class);
    persistentRAF = mock(LockableRandomAccessBufferFactory.class);
    fileRAFTransient = mock(FileRandomAccessBufferFactory.class);
    fileRAFPersistent = mock(FileRandomAccessBufferFactory.class);
    RealCompressor realCompressor = mock(RealCompressor.class);
    DatastoreChecker datastoreChecker = mock(DatastoreChecker.class);
    PersistentRequestRoot persistentRoot = mock(PersistentRequestRoot.class);
    MasterSecret cryptoSecretTransient = mock(MasterSecret.class);
    LinkFilterExceptionProvider linkFilterExceptionProvider =
        mock(LinkFilterExceptionProvider.class);
    HealingQueue healingQueue = mock(HealingQueue.class);
    USKManager uskManager = mock(USKManager.class);
    ArchiveManager archiveManager = mock(ArchiveManager.class);
    jobRunner = new FakeJobRunner();

    // Minimal default contexts used by accessors under test
    defaultFetchCtx =
        new FetchContext(
            FetchContextOptions.builder()
                .limits(1024L, 2048L, 4096)
                .archiveLimits(2, 3, 1, false)
                .retryLimits(1, 1, 0)
                .splitfileLimits(true, 16, 16)
                .behavior(true, false, true)
                .clientOptions(new SimpleEventProducer(), false, true)
                .filterOverrides(null, null, null)
                .build());

    defaultInsertCtx =
        new InsertContext(
            InsertContextOptions.builder()
                .retryLimits(1, 0)
                .splitfileSegmentLimits(16, 16)
                .clientOptions(new SimpleEventProducer(), true, false, false)
                .compressorDescriptor(null)
                .redundancy(0, 0)
                .compatibility(CompatibilityMode.COMPAT_CURRENT)
                .build());

    Config config = new Config();

    ctx =
        new ClientContext(
            BOOT_ID,
            new ClientContextRuntime(
                new ClientLayerPersister(
                    mainExecutor,
                    ticker,
                    null,
                    null,
                    persistentTempBucketFactory,
                    tempBucketFactory,
                    null),
                mainExecutor,
                memoryLimitedJobRunner,
                ticker,
                strongRandom,
                fastWeakRandom,
                cryptoSecretTransient),
            new ClientContextStorageFactories(
                persistentTempBucketFactory,
                tempBucketFactory,
                persistentFileTracker,
                fg,
                persistentFG,
                fileRAFTransient,
                fileRAFPersistent),
            new ClientContextRafFactories(tempRAF, persistentRAF),
            new ClientContextServices(
                new ClientContextResources(archiveManager, healingQueue),
                uskManager,
                realCompressor,
                datastoreChecker,
                persistentRoot,
                linkFilterExceptionProvider),
            new ClientContextDefaults(defaultFetchCtx, defaultInsertCtx, config));

    // Replace the real jobRunner created above with a controllable fake for start() tests
    setField(ctx, "dummyJobRunner", new DummyJobRunner(mainExecutor, ctx));
    setField(ctx, "persistentFileTracker", persistentTempBucketFactory);
    setField(ctx, "jobRunner", jobRunner);
  }

  @Test
  void init_whenCalled_setsAlertsUsedByPostUserAlert() {
    UserAlertManager alerts = mock(UserAlertManager.class);
    // We don't need actual schedulers here; a mock is fine (fields read as null)
    network.crypta.node.RequestStarterGroup starters =
        mock(network.crypta.node.RequestStarterGroup.class);

    ctx.init(starters, alerts);

    UserAlert alert = mock(UserAlert.class);
    ctx.postUserAlert(alert);
    verify(alerts, times(1)).register(alert);
  }

  @Test
  void postUserAlert_whenAlertsNull_schedulesAndRunsLater() {
    // Ensure alerts are null (do not call init())
    UserAlert alert = mock(UserAlert.class);
    ctx.postUserAlert(alert);

    FakeTicker fakeTicker = (FakeTicker) ticker;
    assertEquals("Post alert", fakeTicker.lastName);
    assertEquals(0L, fakeTicker.lastOffset);
    assertNotNull(fakeTicker.lastJob);

    // Set alerts then run the queued job
    UserAlertManager alerts = mock(UserAlertManager.class);
    setField(ctx, "alerts", alerts);
    fakeTicker.runLast();

    verify(alerts, times(1)).register(alert);
  }

  @Test
  void getBucketFactory_whenPersistent_returnsPersistentFactory() {
    assertSame(persistentTempBucketFactory, ctx.getBucketFactory(true));
  }

  @Test
  void getBucketFactory_whenTransient_returnsTempFactory() {
    assertSame(tempBucketFactory, ctx.getBucketFactory(false));
  }

  @Test
  void getFetchScheduler_returnsBasedOnFlags() {
    ClientRequestScheduler sskBulk = mock(ClientRequestScheduler.class);
    ClientRequestScheduler sskRT = mock(ClientRequestScheduler.class);
    ClientRequestScheduler chkBulk = mock(ClientRequestScheduler.class);
    ClientRequestScheduler chkRT = mock(ClientRequestScheduler.class);

    setField(ctx, "sskFetchSchedulerBulk", sskBulk);
    setField(ctx, "sskFetchSchedulerRT", sskRT);
    setField(ctx, "chkFetchSchedulerBulk", chkBulk);
    setField(ctx, "chkFetchSchedulerRT", chkRT);

    assertSame(sskBulk, ctx.getFetchScheduler(true, false));
    assertSame(sskRT, ctx.getFetchScheduler(true, true));
    assertSame(chkBulk, ctx.getFetchScheduler(false, false));
    assertSame(chkRT, ctx.getFetchScheduler(false, true));
  }

  @Test
  void getSpecificSchedulers_returnFieldsByRealtime() {
    ClientRequestScheduler bulk = mock(ClientRequestScheduler.class);
    ClientRequestScheduler rt = mock(ClientRequestScheduler.class);

    setField(ctx, "sskFetchSchedulerBulk", bulk);
    setField(ctx, "sskFetchSchedulerRT", rt);
    assertSame(bulk, ctx.getSskFetchScheduler(false));
    assertSame(rt, ctx.getSskFetchScheduler(true));

    bulk = mock(ClientRequestScheduler.class);
    rt = mock(ClientRequestScheduler.class);
    setField(ctx, "chkFetchSchedulerBulk", bulk);
    setField(ctx, "chkFetchSchedulerRT", rt);
    assertSame(bulk, ctx.getChkFetchScheduler(false));
    assertSame(rt, ctx.getChkFetchScheduler(true));

    bulk = mock(ClientRequestScheduler.class);
    rt = mock(ClientRequestScheduler.class);
    setField(ctx, "sskInsertSchedulerBulk", bulk);
    setField(ctx, "sskInsertSchedulerRT", rt);
    assertSame(bulk, ctx.getSskInsertScheduler(false));
    assertSame(rt, ctx.getSskInsertScheduler(true));

    bulk = mock(ClientRequestScheduler.class);
    rt = mock(ClientRequestScheduler.class);
    setField(ctx, "chkInsertSchedulerBulk", bulk);
    setField(ctx, "chkInsertSchedulerRT", rt);
    assertSame(bulk, ctx.getChkInsertScheduler(false));
    assertSame(rt, ctx.getChkInsertScheduler(true));
  }

  @Test
  void setAndGetPersistentMasterSecret_roundTrips() {
    MasterSecret secret = mock(MasterSecret.class);
    ctx.setPersistentMasterSecret(secret);
    assertSame(secret, ctx.getPersistentMasterSecret());
  }

  @Test
  void getDefaultPersistentFetchContext_returnsCopyWithNewProducer() {
    FetchContext copy = ctx.getDefaultPersistentFetchContext();
    assertNotNull(copy);
    assertNotSame(defaultFetchCtx, copy);
    // Event producer must be a new instance per copy
    assertNotSame(defaultFetchCtx.getEventProducer(), copy.getEventProducer());
    // Some representative field is preserved
    assertEquals(defaultFetchCtx.getMaxRecursionLevel(), copy.getMaxRecursionLevel());
  }

  @Test
  void getDefaultPersistentInsertContext_returnsEquivalentCopy() {
    InsertContext copy = ctx.getDefaultPersistentInsertContext();
    assertNotNull(copy);
    assertNotSame(defaultInsertCtx, copy);
    // Representative fields are preserved; producer differs
    assertEquals(
        defaultInsertCtx.getCompatibilityMode(),
        copy.getCompatibilityMode(),
        "compatibility mode should be preserved");
    assertEquals(
        defaultInsertCtx.getSplitfileSegmentDataBlocks(),
        copy.getSplitfileSegmentDataBlocks(),
        "splitfile data blocks should be preserved");
    assertEquals(
        defaultInsertCtx.getSplitfileSegmentCheckBlocks(),
        copy.getSplitfileSegmentCheckBlocks(),
        "splitfile check blocks should be preserved");
  }

  @Test
  void getJobRunner_returnsPersistentOrDummy() {
    assertSame(jobRunner, ctx.getJobRunner(true));
    PersistentJobRunner nonPersistent = ctx.getJobRunner(false);
    assertNotNull(nonPersistent);
    assertInstanceOf(DummyJobRunner.class, nonPersistent);
  }

  @Test
  void getFileRandomAccessBufferFactory_returnsByPersistence() {
    assertSame(fileRAFPersistent, ctx.getFileRandomAccessBufferFactory(true));
    assertSame(fileRAFTransient, ctx.getFileRandomAccessBufferFactory(false));
  }

  @Test
  void getRandomAccessBufferFactory_returnsByPersistence() {
    // persistent -> persistentRAF
    assertSame(persistentRAF, ctx.getRandomAccessBufferFactory(true));
    // transient -> tempBucketFactory (implements LockableRandomAccessBufferFactory)
    assertSame(tempBucketFactory, ctx.getRandomAccessBufferFactory(false));
  }

  @Test
  void getMainExecutor_returnsProvided() {
    assertSame(mainExecutor, ctx.getMainExecutor());
  }

  @Test
  void startClientPutter_whenPersistent_queuesJobAtNormPriority_andRunsStart() throws Exception {
    ClientPutter putter = mock(ClientPutter.class);
    when(putter.persistent()).thenReturn(true);

    ctx.start(putter);

    assertNotNull(jobRunner.lastJob);
    assertEquals(NativeThread.PriorityLevel.NORM_PRIORITY.value, jobRunner.lastPriority);

    // Execute the queued job -> should call start(false, ctx)
    jobRunner.runLast(ctx);
    verify(putter, times(1)).start(false, ctx);
  }

  @Test
  void startClientPutter_whenPersistent_andStartThrows_invokesCallbackOnFailure() throws Exception {
    ClientPutter putter = mock(ClientPutter.class);
    when(putter.persistent()).thenReturn(true);
    doThrow(new InsertException(InsertException.InsertExceptionMode.INTERNAL_ERROR))
        .when(putter)
        .start(anyBoolean(), any(ClientContext.class));

    ClientPutCallback cb = mock(ClientPutCallback.class);
    setField(putter, "callback", cb);

    ctx.start(putter);
    jobRunner.runLast(ctx);
    verify(cb, times(1)).onFailure(any(InsertException.class), any(BaseClientPutter.class));
  }

  @Test
  void startClientPutter_whenTransient_startsImmediately() throws Exception {
    ClientPutter putter = mock(ClientPutter.class);
    when(putter.persistent()).thenReturn(false);

    ctx.start(putter);

    verify(putter, times(1)).start(false, ctx);
    // No job queued
    assertEquals(0, jobRunner.queueCalls);
  }

  @Test
  void startClientGetter_whenPersistent_andStartThrows_invokesCallbackOnFailure() throws Exception {
    ClientGetter getter = mock(ClientGetter.class);
    when(getter.persistent()).thenReturn(true);
    doThrow(
            new network.crypta.client.FetchException(
                network.crypta.client.FetchException.FetchExceptionMode.INTERNAL_ERROR))
        .when(getter)
        .start(any(ClientContext.class));

    ClientGetCallback cb = mock(ClientGetCallback.class);
    setField(getter, "clientCallback", cb);

    ctx.start(getter);
    jobRunner.runLast(ctx);
    verify(cb, times(1)).onFailure(any(network.crypta.client.FetchException.class));
  }

  @Test
  void startClientGetter_whenTransient_startsImmediately() throws Exception {
    ClientGetter getter = mock(ClientGetter.class);
    when(getter.persistent()).thenReturn(false);

    ctx.start(getter);
    verify(getter, times(1)).start(ctx);
    assertEquals(0, jobRunner.queueCalls);
  }

  @Test
  void startBaseManifestPutter_whenPersistent_andStartThrows_invokesCallbackOnFailure()
      throws Exception {
    BaseManifestPutter putter = mock(BaseManifestPutter.class);
    when(putter.persistent()).thenReturn(true);
    doThrow(new InsertException(InsertException.InsertExceptionMode.INTERNAL_ERROR))
        .when(putter)
        .start(any(ClientContext.class));

    ClientPutCallback cb = mock(ClientPutCallback.class);
    setField(putter, "cb", cb);

    ctx.start(putter);
    jobRunner.runLast(ctx);
    verify(cb, times(1)).onFailure(any(InsertException.class), any());
  }

  @Test
  void startBaseManifestPutter_whenTransient_startsImmediately() throws Exception {
    BaseManifestPutter putter = mock(BaseManifestPutter.class);
    when(putter.persistent()).thenReturn(false);

    ctx.start(putter);
    verify(putter, times(1)).start(ctx);
    assertEquals(0, jobRunner.queueCalls);
  }

  // --------------------- helpers ---------------------

  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field f = target.getClass().getDeclaredField(fieldName);
      f.setAccessible(true);
      f.set(target, value);
    } catch (NoSuchFieldException _) {
      // Try superclass (useful for mocks)
      try {
        Field f = target.getClass().getSuperclass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
      } catch (ReflectiveOperationException ex) {
        throw new AssertionError(ex);
      }
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }

  private static final class FakeJobRunner implements PersistentJobRunner {
    PersistentJob lastJob;
    int lastPriority;
    int queueCalls;

    @Override
    public void queue(PersistentJob persistentJob, int threadPriority) {
      this.lastJob = persistentJob;
      this.lastPriority = threadPriority;
      this.queueCalls++;
    }

    void runLast(ClientContext context) {
      if (lastJob != null) lastJob.run(context);
    }

    @Override
    public void queueNormalOrDrop(PersistentJob persistentJob) {
      this.lastJob = persistentJob;
      this.lastPriority = NativeThread.PriorityLevel.NORM_PRIORITY.value;
      this.queueCalls++;
    }

    @Override
    public void queueInternal(PersistentJob job, int threadPriority) {
      this.lastJob = job;
      this.lastPriority = threadPriority;
      this.queueCalls++;
    }

    @Override
    public void queueInternal(PersistentJob job) {
      this.lastJob = job;
      this.lastPriority = NativeThread.PriorityLevel.NORM_PRIORITY.value;
      this.queueCalls++;
    }

    @Override
    public void setCheckpointASAP() {
      // Intentionally empty for the fake job runner used in tests: we do not
      // model checkpoint scheduling semantics here. Tests assert behavior by
      // inspecting queued jobs and executing them via runLast(...), so an
      // actual checkpoint trigger is unnecessary.
    }

    @Override
    public boolean hasLoaded() {
      return true;
    }

    @Override
    public CheckpointLock lock() {
      return (forceWrite, prio) -> {};
    }

    @Override
    public boolean newSalt() {
      return false;
    }

    @Override
    public boolean shuttingDown() {
      return false;
    }
  }

  private static final class FakeTicker implements Ticker {
    final PriorityAwareExecutor exec;
    Runnable lastJob;
    String lastName;
    long lastOffset;

    FakeTicker(PriorityAwareExecutor exec) {
      this.exec = exec;
    }

    @Override
    public void queueTimedJob(Runnable job, long offset) {
      this.lastJob = job;
      this.lastName = null;
      this.lastOffset = offset;
    }

    @Override
    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
      this.lastJob = job;
      this.lastName = name;
      this.lastOffset = offset;
    }

    void runLast() {
      if (lastJob != null) lastJob.run();
    }

    @Override
    public PriorityAwareExecutor getExecutor() {
      return exec;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      if (lastJob == job) lastJob = null;
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      this.lastJob = runner;
      this.lastName = name;
      this.lastOffset = time;
    }
  }
}
