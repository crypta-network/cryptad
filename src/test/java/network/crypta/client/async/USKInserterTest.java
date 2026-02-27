package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.InsertException;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.USK;
import network.crypta.node.ClientContextResources;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class USKInserterTest {

  @Mock private PutCompletionCallback cb;

  @Mock private BaseClientPutter parent;

  @Mock private USKManager uskManager;

  @Mock private USKFetcherTag fetcherTag;

  @Mock private Bucket metaBucket;

  private ClientContext context;

  private static class InlineExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NonNull Runnable job) {
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
  }

  private record InserterCfg(
      boolean isMetadata,
      boolean addToParent,
      boolean freeData,
      boolean persistent,
      boolean realTimeFlag) {}

  private static class DummyRandomSource extends RandomSource {
    @Serial private static final long serialVersionUID = 1L;

    @Override
    public int acceptEntropy(
        network.crypta.crypt.EntropySource source, long data, int entropyGuess) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(network.crypta.crypt.EntropySource timer) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(network.crypta.crypt.EntropySource fnpTimingSource, double bias) {
      return 0;
    }

    @Override
    public int acceptEntropyBytes(
        network.crypta.crypt.EntropySource myPacketDataSource,
        byte[] buf,
        int offset,
        int length,
        double bias) {
      return 0;
    }

    @Override
    public void close() {
      // No external resources to release in this test stub.
    }
  }

  @BeforeEach
  void setup() {
    context = newContext(null);
  }

  // Helpers in tests create per-test SSKs to build consistent public/insertable USK URIs.

  private static InsertContext newInsertContext() {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(0, 0)
            .splitfileSegmentLimits(0, 0)
            .clientOptions(new SimpleEventProducer(), false, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  private static Bucket makeBucket(byte[] data) {
    // Minimal bucket backed by provided bytes; supports read and free().
    return new Bucket() {
      private boolean freed = false;

      @Override
      public java.io.OutputStream getOutputStream() throws IOException {
        throw new IOException("read-only");
      }

      @Override
      public java.io.OutputStream getOutputStreamUnbuffered() throws IOException {
        throw new IOException("read-only");
      }

      @Override
      public InputStream getInputStream() {
        return new ByteArrayInputStream(data);
      }

      @Override
      public InputStream getInputStreamUnbuffered() {
        return new ByteArrayInputStream(data);
      }

      @Override
      public String getName() {
        return "test-bucket";
      }

      @Override
      public long size() {
        return data.length;
      }

      @Override
      public boolean isReadOnly() {
        return true;
      }

      @Override
      public void setReadOnly() {
        // Bucket is a read-only stub; nothing to change.
      }

      @Override
      public void free() {
        freed = true;
      }

      @Override
      public Bucket createShadow() {
        return null;
      }

      @Override
      public void onResume(ClientContext context) {
        // Not persistent in tests; nothing to resume.
      }

      @Override
      public void storeTo(DataOutputStream dos) {
        // Not persistent in tests; no-op.
      }

      @Override
      public String toString() {
        return "Bucket[freed=" + freed + "]";
      }
    };
  }

  private ClientContext newContext(Ticker ticker) {
    // Minimal ClientContext: only fields touched by these tests are used.
    // Many collaborators are irrelevant here and can be passed as null or simple stubs.
    return new ClientContext(
        1L,
        new ClientContextRuntime(
            Mockito.mock(ClientLayerPersister.class),
            new InlineExecutor(),
            null,
            ticker,
            new DummyRandomSource(),
            new SecureRandom(),
            null),
        new ClientContextStorageFactories(null, null, null, null, null, null, null),
        new ClientContextRafFactories(null, null),
        new ClientContextServices(
            new ClientContextResources(null, null), uskManager, null, null, null, null),
        new ClientContextDefaults(
            // Default persistent contexts used only when building fetchers internally; not
            // exercised in these tests.
            new FetchContext(
                FetchContextOptions.builder()
                    .limits(0, 0, 0)
                    .archiveLimits(1, 0, 0, true)
                    .retryLimits(0, 0, 0)
                    .splitfileLimits(false, 0, 0)
                    .behavior(false, false, false)
                    .clientOptions(new SimpleEventProducer(), false, false)
                    .filterOverrides(null, null, null)
                    .build()),
            newInsertContext(),
            null));
  }

  private USKInserter newInserter(
      Bucket data,
      short compressionCodec,
      FreenetURI uskUri,
      InsertContext insertCtx,
      InserterCfg cfg)
      throws Exception {
    // Parent getClient() is consulted when scheduling a fetcher; we provide a minimal mock.
    var rc = Mockito.mock(network.crypta.node.RequestClient.class);
    Mockito.lenient().when(parent.getClient()).thenReturn(rc);
    Mockito.lenient().when(rc.persistent()).thenReturn(cfg.persistent);
    Mockito.lenient().when(rc.realTimeFlag()).thenReturn(cfg.realTimeFlag);

    return new USKInserter(
        new BlockInsertPayload(
            data,
            uskUri,
            compressionCodec,
            cfg.isMetadata,
            (int) data.size(),
            Key.ALGO_AES_PCFB_256_SHA256,
            null),
        new BlockInsertParams(parent, insertCtx, cb, 123, "token", cfg.addToParent, context),
        new BlockInsertOptions(cfg.persistent, cfg.realTimeFlag, cfg.freeData, 0));
  }

  private static Object newDateHintTerminalCallback(
      USKInserter inserter, long phaseId, long edition) throws Exception {
    return newDateHintTerminalCallback(inserter, phaseId, edition, 0);
  }

  private static Object newDateHintTerminalCallback(
      USKInserter inserter, long phaseId, long edition, int retryCount) throws Exception {
    Class<?> callbackClass =
        Class.forName(USKInserter.class.getName() + "$DateHintTerminalCallback");
    Constructor<?> ctor =
        callbackClass.getDeclaredConstructor(USKInserter.class, long.class, long.class, int.class);
    ctor.setAccessible(true);
    return ctor.newInstance(inserter, phaseId, edition, retryCount);
  }

  private static Object newDateHintPhase(long phaseId, Object callback) throws Exception {
    return newDateHintPhase(phaseId, 0, callback, Mockito.mock(ClientPutState.class));
  }

  private static Object newDateHintPhase(
      long phaseId, int retryCount, Object callback, ClientPutState completionState)
      throws Exception {
    Class<?> callbackClass =
        Class.forName(USKInserter.class.getName() + "$DateHintTerminalCallback");
    Class<?> phaseClass = Class.forName(USKInserter.class.getName() + "$DateHintPhase");
    Constructor<?> ctor =
        phaseClass.getDeclaredConstructor(
            long.class, int.class, callbackClass, ClientPutState.class);
    ctor.setAccessible(true);
    return ctor.newInstance(phaseId, retryCount, callback, completionState);
  }

  private static void setDateHintCallbackGroup(Object callback, MultiPutCompletionCallback group)
      throws Exception {
    Field f = callback.getClass().getDeclaredField("group");
    f.setAccessible(true);
    f.set(callback, group);
  }

  private static void setDateHintLastProgressAtMillis(Object phase, long value) throws Exception {
    Field f = phase.getClass().getDeclaredField("lastProgressAtMillis");
    f.setAccessible(true);
    f.setLong(phase, value);
  }

  private static boolean isDateHintWatchdogCancelIssued(Object phase) throws Exception {
    Field f = phase.getClass().getDeclaredField("watchdogCancelIssued");
    f.setAccessible(true);
    return f.getBoolean(phase);
  }

  private static void setDateHintWatchdogCancelIssued(Object phase) throws Exception {
    Field f = phase.getClass().getDeclaredField("watchdogCancelIssued");
    f.setAccessible(true);
    f.setBoolean(phase, true);
  }

  private static void setDateHintWatchdogCancelIssuedAtMillis(Object phase, long value)
      throws Exception {
    Field f = phase.getClass().getDeclaredField("watchdogCancelIssuedAtMillis");
    f.setAccessible(true);
    f.setLong(phase, value);
  }

  private static long getDateHintCancelCompletionTimeoutMillis() throws Exception {
    Field f = USKInserter.class.getDeclaredField("DATEHINT_CANCEL_COMPLETION_TIMEOUT_MILLIS");
    f.setAccessible(true);
    return f.getLong(null);
  }

  private static void setActiveDateHintPhase(USKInserter inserter, Object phase) throws Exception {
    Field activeField = USKInserter.class.getDeclaredField("activeDateHintPhase");
    activeField.setAccessible(true);
    activeField.set(inserter, phase);
  }

  private static Object getActiveDateHintPhase(USKInserter inserter) throws Exception {
    Field activeField = USKInserter.class.getDeclaredField("activeDateHintPhase");
    activeField.setAccessible(true);
    return activeField.get(inserter);
  }

  private static void setDateHintTerminalAwaitingPhaseRestore(
      PutCompletionCallback callback, boolean inProgress) throws Exception {
    Field restoreField = callback.getClass().getDeclaredField("awaitingPhaseRestore");
    restoreField.setAccessible(true);
    restoreField.setBoolean(callback, inProgress);
  }

  private static void setDateHintTerminalWatchdogCancelIssued(PutCompletionCallback callback)
      throws Exception {
    Field f = callback.getClass().getDeclaredField("watchdogCancelIssued");
    f.setAccessible(true);
    f.setBoolean(callback, true);
  }

  private static long getDateHintStallTimeoutMillis() throws Exception {
    Field f = USKInserter.class.getDeclaredField("DATEHINT_STALL_TIMEOUT_MILLIS");
    f.setAccessible(true);
    return f.getLong(null);
  }

  private static void runDateHintWatchdog(USKInserter inserter, ClientContext context, long phaseId)
      throws Exception {
    Method watchdog =
        USKInserter.class.getDeclaredMethod("runDateHintWatchdog", ClientContext.class, long.class);
    watchdog.setAccessible(true);
    watchdog.invoke(inserter, context, phaseId);
  }

  @Test
  void schedule_whenCalled_schedulesFetcher() throws Exception {
    // Arrange
    String site = "mysite";
    long edition = 10L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    byte[] bytes = "data".getBytes(StandardCharsets.UTF_8);
    Bucket bucket = makeBucket(bytes);

    InsertContext ic = newInsertContext();
    ic.setIgnoreUSKDatehints(false);

    when(uskManager.getFetcherForInsertDontSchedule(
            any(USK.class),
            any(short.class),
            any(USKFetcherCallback.class),
            any(),
            any(ClientContext.class),
            any(Boolean.class),
            any(Boolean.class)))
        .thenReturn(fetcherTag);

    USKInserter inserter =
        newInserter(
            bucket, (short) 1, insertUri, ic, new InserterCfg(false, false, false, false, false));

    // Act
    inserter.schedule(context);

    // Assert
    verify(fetcherTag, times(1)).schedule(context);
  }

  @Test
  void schedule_whenCancelledBeforeFetcherSchedule_doesNotScheduleFetcher() throws Exception {
    byte[] bytes = "race".getBytes(StandardCharsets.UTF_8);
    Bucket bucket = makeBucket(bytes);
    String site = "race-site";
    long edition = 10L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);

    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            bucket, (short) 1, insertUri, ic, new InserterCfg(false, false, true, false, false));

    doAnswer(
            _ -> {
              inserter.cancel(context);
              return fetcherTag;
            })
        .when(uskManager)
        .getFetcherForInsertDontSchedule(
            any(USK.class),
            any(short.class),
            any(USKFetcherCallback.class),
            any(),
            any(ClientContext.class),
            any(Boolean.class),
            any(Boolean.class));

    inserter.schedule(context);

    verify(fetcherTag, times(0)).schedule(context);
  }

  @Test
  void onFoundEdition_whenDataAndCodecMatch_expectAlreadyInsertedAndSuccessCallbacks()
      throws Exception {
    // Arrange: prepare data and matching hisData/codec/metadata
    byte[] bytes = "hello".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "mysite";
    long edition = 5L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    USK publicUSK =
        USK.create(
            new FreenetURI(
                "USK",
                site,
                null,
                ssk.pubKeyHash,
                ssk.cryptoKey,
                ssk.getURI().getExtra(),
                edition));

    InsertContext ic = newInsertContext();
    ic.setIgnoreUSKDatehints(true); // skip USK date hints path for determinism

    USKInserter inserter =
        newInserter(
            data, (short) 3, insertUri, ic, new InserterCfg(false, false, true, false, false));

    // Act: Found a matching edition with identical data
    long foundEdition = 7L;
    inserter.onFoundEdition(
        new USKFoundEdition(
            new USKFoundEditionPayload(foundEdition, publicUSK, false, (short) 3, bytes),
            context,
            new USKFoundEditionProgress(true, true)));

    // Assert: parent and callback methods invoked; success path without date hints
    verify(parent, times(1)).completedBlock(true, context);

    ArgumentCaptor<USK> uskCaptor = ArgumentCaptor.forClass(USK.class);
    verify(cb, times(1)).onEncode(uskCaptor.capture(), any(), any());
    assertEquals(foundEdition, uskCaptor.getValue().suggestedEdition);

    verify(cb, times(1)).onSuccess(any(), any());
  }

  @Test
  void onSuccess_whenURIsMatch_updatesKnownGood_andEncodesAndSucceeds() throws Exception {
    // Arrange
    byte[] bytes = "payload".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "site";
    long edition = 12;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);

    InsertContext ic = newInsertContext();
    ic.setIgnoreUSKDatehints(true); // deterministic: avoid date hints branch

    USKInserter inserter =
        newInserter(
            data, (short) 1, insertUri, ic, new InserterCfg(false, false, true, false, false));

    // The inserter computes targetURI from pubUSK + current edition (initial suggested edition).
    USK pub =
        USK.create(
            new FreenetURI(
                "USK",
                site,
                null,
                ssk.pubKeyHash,
                ssk.cryptoKey,
                ssk.getURI().getExtra(),
                edition));
    FreenetURI targetURI = pub.getSSK(edition).getURI();

    // Mock SingleBlockInserter state to report the expected URI
    SingleBlockInserter state = Mockito.mock(SingleBlockInserter.class);
    when(state.getURI(context)).thenReturn(targetURI);

    // Act
    inserter.onSuccess(state, context);

    // Assert: Update known good, encode callback and success invoked
    verify(uskManager, times(1)).updateKnownGood(pub, edition, context);
    verify(cb, times(1)).onEncode(any(), any(), any());
    verify(cb, times(1)).onSuccess(any(), any());
  }

  @Test
  void cancel_whenActive_cancelsFetcher_freesData_andEmitsCancelledFailure() throws Exception {
    // Arrange
    byte[] bytes = "cancel-me".getBytes(StandardCharsets.UTF_8);
    Bucket data = Mockito.spy(makeBucket(bytes));
    String site = "abc";
    long edition = 1L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);

    InsertContext ic = newInsertContext();

    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, true, false, false));

    // Ensure a fetcher exists by scheduling once so cancel() can cancel it.
    when(uskManager.getFetcherForInsertDontSchedule(
            any(USK.class),
            any(short.class),
            any(USKFetcherCallback.class),
            any(),
            any(ClientContext.class),
            any(Boolean.class),
            any(Boolean.class)))
        .thenReturn(fetcherTag);
    inserter.schedule(context);

    // Act
    inserter.cancel(context);

    // Assert
    verify(fetcherTag, times(1)).cancel(context);
    verify(data, times(1)).free();

    ArgumentCaptor<InsertException> ex = ArgumentCaptor.forClass(InsertException.class);
    verify(cb, times(1)).onFailure(ex.capture(), any(), any());
    assertEquals(InsertExceptionMode.CANCELLED, ex.getValue().getMode());
  }

  @Test
  void runDateHintWatchdog_whenPhaseStalled_cancelsActiveDateHintGroup() throws Exception {
    // Arrange
    byte[] bytes = "stalled-datehint".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "watchdog-stall";
    long edition = 5L;
    long phaseId = 91L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();

    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, false, false));

    MultiPutCompletionCallback group = Mockito.mock(MultiPutCompletionCallback.class);
    Object callback = newDateHintTerminalCallback(inserter, phaseId, edition);
    setDateHintCallbackGroup(callback, group);
    Object phase = newDateHintPhase(phaseId, callback);
    setDateHintLastProgressAtMillis(phase, 0L);
    setActiveDateHintPhase(inserter, phase);

    // Act
    runDateHintWatchdog(inserter, context, phaseId);

    // Assert
    verify(group, times(1)).cancel(context);
    assertTrue(isDateHintWatchdogCancelIssued(phase));
  }

  @Test
  void runDateHintWatchdog_whenRecentProgress_reschedulesWithoutCancelling() throws Exception {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    ClientContext contextWithTicker = newContext(ticker);
    byte[] bytes = "recent-datehint".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "watchdog-reschedule";
    long edition = 9L;
    long phaseId = 92L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();

    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, false, false));

    MultiPutCompletionCallback group = Mockito.mock(MultiPutCompletionCallback.class);
    Object callback = newDateHintTerminalCallback(inserter, phaseId, edition);
    setDateHintCallbackGroup(callback, group);
    Object phase = newDateHintPhase(phaseId, callback);
    setDateHintLastProgressAtMillis(phase, System.currentTimeMillis());
    setActiveDateHintPhase(inserter, phase);

    // Act
    runDateHintWatchdog(inserter, contextWithTicker, phaseId);

    // Assert
    verify(group, never()).cancel(any(ClientContext.class));
    verify(ticker, times(1))
        .queueTimedJob(any(Runnable.class), Mockito.longThat(delay -> delay > 0L));
    assertFalse(isDateHintWatchdogCancelIssued(phase));
  }

  @Test
  void runDateHintWatchdog_whenSchedulerCooldownActive_reschedulesWithoutCancelling()
      throws Exception {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    ClientContext contextWithTicker = Mockito.spy(newContext(ticker));
    ClientRequestScheduler scheduler = Mockito.mock(ClientRequestScheduler.class);
    when(contextWithTicker.getSskInsertScheduler(false)).thenReturn(scheduler);
    when(parent.getPriorityClass()).thenReturn((short) 2);
    when(scheduler.getPriorityCooldownUntil(Mockito.eq((short) 2), Mockito.anyLong()))
        .thenAnswer(
            invocation -> ((Long) invocation.getArgument(1)) + TimeUnit.MINUTES.toMillis(20));

    byte[] bytes = "scheduler-cooldown-datehint".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "watchdog-scheduler-cooldown";
    long edition = 10L;
    long phaseId = 94L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();

    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, false, false));

    MultiPutCompletionCallback group = Mockito.mock(MultiPutCompletionCallback.class);
    Object callback = newDateHintTerminalCallback(inserter, phaseId, edition);
    setDateHintCallbackGroup(callback, group);
    Object phase = newDateHintPhase(phaseId, callback);
    setDateHintLastProgressAtMillis(phase, 0L);
    setActiveDateHintPhase(inserter, phase);

    // Act
    runDateHintWatchdog(inserter, contextWithTicker, phaseId);

    // Assert
    verify(group, never()).cancel(any(ClientContext.class));
    verify(scheduler, times(1)).getPriorityCooldownUntil(Mockito.eq((short) 2), Mockito.anyLong());
    verify(ticker, times(1))
        .queueTimedJob(
            any(Runnable.class), Mockito.longThat(delay -> delay >= TimeUnit.MINUTES.toMillis(20)));
    assertFalse(isDateHintWatchdogCancelIssued(phase));
  }

  @Test
  void runDateHintWatchdog_whenCancelDoesNotComplete_forceCompletesPhaseAsBestEffortSuccess()
      throws Exception {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    ClientContext contextWithTicker = newContext(ticker);
    byte[] bytes = "watchdog-force-complete".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "watchdog-force-complete-site";
    long edition = 12L;
    long phaseId = 95L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, false, false));

    MultiPutCompletionCallback group = Mockito.mock(MultiPutCompletionCallback.class);
    PutCompletionCallback terminalCallback =
        (PutCompletionCallback) newDateHintTerminalCallback(inserter, phaseId, edition, 1);
    setDateHintCallbackGroup(terminalCallback, group);
    ClientPutState transitionedState = Mockito.mock(ClientPutState.class);
    Object phase = newDateHintPhase(phaseId, 1, terminalCallback, transitionedState);
    setDateHintLastProgressAtMillis(phase, 0L);
    setActiveDateHintPhase(inserter, phase);

    // Act: the first watchdog pass cancels, the second pass force-completes after grace timeout.
    runDateHintWatchdog(inserter, contextWithTicker, phaseId);
    long timeoutMillis = getDateHintCancelCompletionTimeoutMillis();
    setDateHintWatchdogCancelIssuedAtMillis(
        phase, System.currentTimeMillis() - timeoutMillis - TimeUnit.SECONDS.toMillis(1));
    runDateHintWatchdog(inserter, contextWithTicker, phaseId);

    // Assert
    verify(group, times(1)).cancel(contextWithTicker);
    verify(ticker, times(1)).queueTimedJob(any(Runnable.class), Mockito.eq(timeoutMillis));
    ArgumentCaptor<ClientPutState> stateCaptor = ArgumentCaptor.forClass(ClientPutState.class);
    verify(cb, times(1)).onSuccess(stateCaptor.capture(), any(ClientContext.class));
    assertSame(transitionedState, stateCaptor.getValue());
    verify(cb, never()).onFailure(any(InsertException.class), any(ClientPutState.class), any());
    assertNull(getActiveDateHintPhase(inserter));
  }

  @Test
  void dateHintTerminalCallback_onResume_restoresWatchdogCancelMarker() throws Exception {
    // Arrange
    byte[] bytes = "watchdog-restore-marker".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "watchdog-restore";
    long edition = 11L;
    long phaseId = 93L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, true, false));

    MultiPutCompletionCallback group = Mockito.mock(MultiPutCompletionCallback.class);
    PutCompletionCallback terminalCallback =
        (PutCompletionCallback) newDateHintTerminalCallback(inserter, phaseId, edition);
    setDateHintCallbackGroup(terminalCallback, group);
    Object phase = newDateHintPhase(phaseId, terminalCallback);
    setDateHintLastProgressAtMillis(phase, 0L);
    setActiveDateHintPhase(inserter, phase);

    // Trigger the watchdog cancellation marker, then simulate restart by dropping the transient
    // phase
    // state.
    runDateHintWatchdog(inserter, context, phaseId);
    setActiveDateHintPhase(inserter, null);

    // Act
    terminalCallback.onResume(context);

    // Assert
    Object restoredPhase = getActiveDateHintPhase(inserter);
    assertTrue(isDateHintWatchdogCancelIssued(restoredPhase));
  }

  @Test
  void dateHintTerminalCallback_onResume_whenWatchdogCancelled_usesCancelTimeoutWatchdog()
      throws Exception {
    // Arrange
    Ticker ticker = Mockito.mock(Ticker.class);
    ClientContext contextWithTicker = newContext(ticker);
    byte[] bytes = "watchdog-resume-cancel-timeout".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "watchdog-resume-cancel-timeout";
    long edition = 12L;
    long phaseId = 96L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, true, false));

    PutCompletionCallback terminalCallback =
        (PutCompletionCallback) newDateHintTerminalCallback(inserter, phaseId, edition, 1);
    setDateHintTerminalWatchdogCancelIssued(terminalCallback);

    // Simulate a restored callback where the transient phase must be rebuilt on resume.
    setActiveDateHintPhase(inserter, null);

    // Act
    terminalCallback.onResume(contextWithTicker);

    // Assert
    long cancelTimeoutMillis = getDateHintCancelCompletionTimeoutMillis();
    long stallTimeoutMillis = getDateHintStallTimeoutMillis();
    verify(ticker, times(1))
        .queueTimedJob(
            any(Runnable.class),
            Mockito.longThat(delay -> delay > 0L && delay <= cancelTimeoutMillis));
    verify(ticker, never())
        .queueTimedJob(any(Runnable.class), Mockito.longThat(delay -> delay >= stallTimeoutMillis));
  }

  @Test
  void dateHintTerminalCallback_onSuccess_forwardsTransitionedStateToParentCallback()
      throws Exception {
    // Arrange
    byte[] bytes = "datehint-success".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "datehint-success-site";
    long edition = 4L;
    long phaseId = 301L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, false, false));

    PutCompletionCallback terminalCallback =
        (PutCompletionCallback) newDateHintTerminalCallback(inserter, phaseId, edition);
    Object phase = newDateHintPhase(phaseId, terminalCallback);
    setActiveDateHintPhase(inserter, phase);

    ClientPutState transitionedState = Mockito.mock(ClientPutState.class);

    // Act
    terminalCallback.onSuccess(transitionedState, context);

    // Assert
    ArgumentCaptor<ClientPutState> stateCaptor = ArgumentCaptor.forClass(ClientPutState.class);
    verify(cb, times(1)).onSuccess(stateCaptor.capture(), any(ClientContext.class));
    assertSame(transitionedState, stateCaptor.getValue());
  }

  @Test
  void dateHintTerminalCallback_onFailure_forwardsTransitionedStateToParentCallback()
      throws Exception {
    // Arrange
    byte[] bytes = "datehint-failure".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "datehint-failure-site";
    long edition = 6L;
    long phaseId = 302L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, false, false));

    PutCompletionCallback terminalCallback =
        (PutCompletionCallback) newDateHintTerminalCallback(inserter, phaseId, edition);
    Object phase = newDateHintPhase(phaseId, terminalCallback);
    setActiveDateHintPhase(inserter, phase);

    ClientPutState transitionedState = Mockito.mock(ClientPutState.class);
    InsertException failure = new InsertException(InsertExceptionMode.INTERNAL_ERROR);

    // Act
    terminalCallback.onFailure(failure, transitionedState, context);

    // Assert
    ArgumentCaptor<ClientPutState> stateCaptor = ArgumentCaptor.forClass(ClientPutState.class);
    verify(cb, times(1)).onFailure(any(InsertException.class), stateCaptor.capture(), any());
    assertSame(transitionedState, stateCaptor.getValue());
  }

  @Test
  void dateHintTerminalCallback_onSuccess_whenPhaseMissingDuringResumeRestore_forwardsSuccess()
      throws Exception {
    // Arrange
    byte[] bytes = "datehint-resume-race".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "datehint-resume-race-site";
    long edition = 7L;
    long phaseId = 401L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, true, false));

    PutCompletionCallback terminalCallback =
        (PutCompletionCallback) newDateHintTerminalCallback(inserter, phaseId, edition);
    setDateHintTerminalAwaitingPhaseRestore(terminalCallback, true);

    ClientPutState transitionedState = Mockito.mock(ClientPutState.class);

    // Act
    terminalCallback.onSuccess(transitionedState, context);

    // Assert
    verify(cb, times(1)).onSuccess(Mockito.eq(transitionedState), any(ClientContext.class));
  }

  @Test
  void dateHintTerminalCallback_onFailure_whenWatchdogCancelledBeforePhaseRestore_treatsAsSuccess()
      throws Exception {
    // Arrange
    byte[] bytes = "datehint-resume-watchdog-cancel".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "datehint-resume-watchdog-cancel-site";
    long edition = 7L;
    long phaseId = 405L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, true, false));

    PutCompletionCallback terminalCallback =
        (PutCompletionCallback) newDateHintTerminalCallback(inserter, phaseId, edition, 1);
    setDateHintTerminalAwaitingPhaseRestore(terminalCallback, true);
    setDateHintTerminalWatchdogCancelIssued(terminalCallback);

    ClientPutState transitionedState = Mockito.mock(ClientPutState.class);
    InsertException cancelled = new InsertException(InsertExceptionMode.CANCELLED);

    // Act
    terminalCallback.onFailure(cancelled, transitionedState, context);

    // Assert
    verify(cb, times(1)).onSuccess(Mockito.eq(transitionedState), any(ClientContext.class));
    verify(cb, never()).onFailure(any(InsertException.class), any(ClientPutState.class), any());
  }

  @Test
  void dateHintTerminalCallback_onSuccess_whenPhaseMissingOutsideResumeRestore_ignoresEvent()
      throws Exception {
    // Arrange
    byte[] bytes = "datehint-missing-phase".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "datehint-missing-phase-site";
    long edition = 8L;
    long phaseId = 402L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, true, false));

    PutCompletionCallback terminalCallback =
        (PutCompletionCallback) newDateHintTerminalCallback(inserter, phaseId, edition);
    setDateHintTerminalAwaitingPhaseRestore(terminalCallback, false);

    ClientPutState transitionedState = Mockito.mock(ClientPutState.class);

    // Act
    terminalCallback.onSuccess(transitionedState, context);

    // Assert
    verify(cb, never()).onSuccess(any(ClientPutState.class), any(ClientContext.class));
  }

  @Test
  void dateHintTerminalCallback_onFailure_whenParentCancelled_doesNotRetryDatehintPhase()
      throws Exception {
    // Arrange
    byte[] bytes = "datehint-cancel-guard".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "datehint-cancel-guard-site";
    long edition = 9L;
    long phaseId = 403L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, false, false));
    when(parent.isCancelled()).thenReturn(true);

    PutCompletionCallback terminalCallback =
        (PutCompletionCallback) newDateHintTerminalCallback(inserter, phaseId, edition);
    Object phase = newDateHintPhase(phaseId, terminalCallback);
    setDateHintWatchdogCancelIssued(phase);
    setActiveDateHintPhase(inserter, phase);

    ClientPutState transitionedState = Mockito.mock(ClientPutState.class);
    InsertException cancelled = new InsertException(InsertExceptionMode.CANCELLED);

    // Act
    terminalCallback.onFailure(cancelled, transitionedState, context);

    // Assert
    verify(cb, times(1))
        .onFailure(Mockito.eq(cancelled), Mockito.eq(transitionedState), any(ClientContext.class));
    verify(cb, never()).onTransition(any(ClientPutState.class), any(ClientPutState.class), any());
  }

  @Test
  void dateHintTerminalCallback_onFailure_whenParentCancelsBeforeRetryStart_skipsRetry()
      throws Exception {
    // Arrange
    byte[] bytes = "datehint-cancel-race".getBytes(StandardCharsets.UTF_8);
    Bucket data = makeBucket(bytes);
    String site = "datehint-cancel-race-site";
    long edition = 10L;
    long phaseId = 404L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, false, false, false));
    when(parent.isCancelled()).thenReturn(false, true);

    PutCompletionCallback terminalCallback =
        (PutCompletionCallback) newDateHintTerminalCallback(inserter, phaseId, edition);
    Object phase = newDateHintPhase(phaseId, terminalCallback);
    setDateHintWatchdogCancelIssued(phase);
    setActiveDateHintPhase(inserter, phase);

    ClientPutState transitionedState = Mockito.mock(ClientPutState.class);
    InsertException cancelled = new InsertException(InsertExceptionMode.CANCELLED);

    // Act
    terminalCallback.onFailure(cancelled, transitionedState, context);

    // Assert
    verify(cb, never()).onTransition(any(ClientPutState.class), any(ClientPutState.class), any());
    verify(cb, never()).onSuccess(any(ClientPutState.class), any(ClientContext.class));
    verify(cb, never()).onFailure(any(InsertException.class), any(ClientPutState.class), any());
    assertNull(getActiveDateHintPhase(inserter));
  }

  @Test
  void onFailure_afterCancelAndDataReleased_doesNotThrow() throws Exception {
    byte[] bytes = "late-cancel".getBytes(StandardCharsets.UTF_8);
    Bucket data = Mockito.spy(makeBucket(bytes));
    String site = "late";
    long edition = 1L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);

    InsertContext ic = newInsertContext();
    USKInserter inserter =
        newInserter(
            data, (short) 0, insertUri, ic, new InserterCfg(false, false, true, false, false));

    inserter.cancel(context);

    assertDoesNotThrow(
        () ->
            inserter.onFailure(
                new InsertException(InsertExceptionMode.CANCELLED),
                Mockito.mock(ClientPutState.class),
                context));

    verify(data, times(1)).free();
  }

  @Test
  void onMetadataBucket_whenCalled_freesBucket() {
    // Arrange
    String site = "x";
    long edition = 1L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    USKInserter inserter;
    try {
      inserter =
          newInserter(
              Mockito.mock(Bucket.class),
              (short) 0,
              insertUri,
              ic,
              new InserterCfg(false, false, false, false, false));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }

    // Act
    inserter.onMetadata(metaBucket, inserter, context);

    // Assert
    verify(metaBucket, times(1)).free();
  }

  @Test
  void getTokenAndPollingPriority_returnProvidedValues() throws Exception {
    // Arrange
    String site = "p";
    long edition = 2L;
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(), site);
    FreenetURI insertUri =
        new FreenetURI(
            "USK",
            site,
            null,
            ssk.getInsertURI().getRoutingKey(),
            ssk.getInsertURI().getCryptoKey(),
            ssk.getInsertURI().getExtra(),
            edition);
    InsertContext ic = newInsertContext();
    Bucket data = makeBucket("t".getBytes(StandardCharsets.UTF_8));
    doReturn((short) 42).when(parent).getPriorityClass();

    USKInserter inserter =
        new USKInserter(
            new BlockInsertPayload(
                data, insertUri, (short) 0, false, 1, Key.ALGO_AES_PCFB_256_SHA256, null),
            new BlockInsertParams(parent, ic, cb, 7, "tok", false, context),
            new BlockInsertOptions(false, false, false, 0));

    // Assert
    assertSame("tok", inserter.getToken());
    assertEquals(42, inserter.getPollingPriorityNormal());
    assertEquals(42, inserter.getPollingPriorityProgress());
  }

  @Test
  void onResume_callsAllCollaboratorsOnce() throws Exception {
    // Arrange
    Bucket data = Mockito.mock(Bucket.class);
    String site2 = "z";
    long edition2 = 3L;
    InsertableClientSSK ssk2 = InsertableClientSSK.createRandom(new DummyRandomSource(), site2);
    FreenetURI insertUri2 =
        new FreenetURI(
            "USK",
            site2,
            null,
            ssk2.getInsertURI().getRoutingKey(),
            ssk2.getInsertURI().getCryptoKey(),
            ssk2.getInsertURI().getExtra(),
            edition2);
    InsertContext ic = newInsertContext();

    USKInserter inserter =
        newInserter(
            data, (short) 1, insertUri2, ic, new InserterCfg(false, false, false, false, false));

    // Create a fetcher via schedule so onResume delegates to it.
    when(uskManager.getFetcherForInsertDontSchedule(
            any(USK.class),
            any(short.class),
            any(USKFetcherCallback.class),
            any(),
            any(ClientContext.class),
            any(Boolean.class),
            any(Boolean.class)))
        .thenReturn(fetcherTag);
    inserter.schedule(context);

    // Act: the first call should notify; the second call should be ignored
    inserter.onResume(context);
    inserter.onResume(context);

    // Assert
    verify(data, times(1)).onResume(context);
    verify(cb, times(1)).onResume(context);
    verify(fetcherTag, times(1)).onResume(context);
  }

  @Test
  void onFailure_whenNonCollision_callsCallbackAndFreesData() throws Exception {
    // Arrange
    byte[] bytes2 = "err".getBytes(StandardCharsets.UTF_8);
    Bucket data2 = Mockito.spy(makeBucket(bytes2));
    String site3 = "errsite";
    long edition3 = 4L;
    InsertableClientSSK ssk3 = InsertableClientSSK.createRandom(new DummyRandomSource(), site3);
    FreenetURI insertUri3 =
        new FreenetURI(
            "USK",
            site3,
            null,
            ssk3.getInsertURI().getRoutingKey(),
            ssk3.getInsertURI().getCryptoKey(),
            ssk3.getInsertURI().getExtra(),
            edition3);
    InsertContext ic = newInsertContext();

    USKInserter inserter =
        newInserter(
            data2, (short) 1, insertUri3, ic, new InserterCfg(false, false, true, false, false));

    // Act
    InsertException ex2 = new InsertException(InsertExceptionMode.BUCKET_ERROR);
    inserter.onFailure(ex2, Mockito.mock(ClientPutState.class), context);

    // Assert
    verify(cb, times(1)).onFailure(Mockito.eq(ex2), any(), any());
    verify(data2, times(1)).free();
  }
}
