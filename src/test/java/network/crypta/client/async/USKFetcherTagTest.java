package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.util.Arrays;
import network.crypta.client.ArchiveManager;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.config.Config;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SHA256;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.node.ClientContextResources;
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
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class USKFetcherTagTest {

  // -------------- Minimal direct helpers (copied from existing tests) --------------

  private static final class DirectExecutor implements PriorityAwareExecutor {
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

  private static final class DirectTicker implements Ticker {
    private final PriorityAwareExecutor executor = new DirectExecutor();

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
      return executor;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      // no-op
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      runner.run();
    }
  }

  private static FetchContext newFetchContext() {
    // Small, deterministic limits; context is forwarded only.
    return new FetchContext(
        FetchContextOptions.builder()
            .limits(16L * 1024, 16L * 1024, 4096)
            .archiveLimits(4, 0, 2, false)
            .retryLimits(1, 1, 1)
            .splitfileLimits(true, 0, 0)
            .behavior(true, false, false)
            .clientOptions(new SimpleEventProducer(), true, true)
            .filterOverrides(null, null, null)
            .build());
  }

  private static InsertContext newInsertContext() {
    return new InsertContext(
        InsertContextOptions.builder()
            .retryLimits(0, 0)
            .splitfileSegmentLimits(0, 0)
            .clientOptions(new SimpleEventProducer(), true, false, false)
            .compressorDescriptor(null)
            .redundancy(0, 0)
            .compatibility(InsertContext.CompatibilityMode.COMPAT_CURRENT)
            .build());
  }

  private static ClientContext minimalContext(
      ClientLayerPersister jobRunner,
      LinkFilterExceptionProvider linkFilterExceptionProvider,
      FetchContext defaultPF,
      InsertContext defaultPI,
      USKManager uskManager,
      PersistentTempBucketFactory ptbf,
      TempBucketFactory tbf) {
    return new ClientContext(
        1L,
        new ClientContextRuntime(
            jobRunner,
            new DirectExecutor(),
            Mockito.mock(MemoryLimitedJobRunner.class),
            new DirectTicker(),
            Mockito.mock(RandomSource.class),
            new java.util.Random(123),
            Mockito.mock(MasterSecret.class)),
        new ClientContextStorageFactories(
            ptbf,
            tbf,
            Mockito.mock(PersistentFileTracker.class),
            Mockito.mock(FilenameGenerator.class),
            Mockito.mock(FilenameGenerator.class),
            Mockito.mock(FileRandomAccessBufferFactory.class),
            Mockito.mock(FileRandomAccessBufferFactory.class)),
        new ClientContextRafFactories(
            Mockito.mock(LockableRandomAccessBufferFactory.class),
            Mockito.mock(LockableRandomAccessBufferFactory.class)),
        new ClientContextServices(
            new ClientContextResources(
                Mockito.mock(ArchiveManager.class), Mockito.mock(HealingQueue.class)),
            uskManager,
            Mockito.mock(RealCompressor.class),
            Mockito.mock(DatastoreChecker.class),
            Mockito.mock(PersistentRequestRoot.class),
            linkFilterExceptionProvider),
        new ClientContextDefaults(defaultPF, defaultPI, Mockito.mock(Config.class)));
  }

  // ---------------- Test fixture ----------------

  private USK usk;
  private FetchContext fetchContext;

  @Mock private USKManager uskManager;
  @Mock private USKFetcher fetcher;
  @Mock private ClientContext mockContext;

  @BeforeEach
  void setup() throws MalformedURLException {
    // Deterministic key material for USK
    DSAPublicKey pubKey = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(2));
    byte[] pubKeyHash = SHA256.digest(pubKey.asBytes());
    byte[] cryptoKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    Arrays.fill(cryptoKey, (byte) 0x2A);
    byte cryptoAlgorithm = Key.ALGO_AES_PCFB_256_SHA256;
    byte[] extras =
        new byte[] {NodeSSK.SSK_VERSION, 0, cryptoAlgorithm, 0, (byte) KeyBlock.HASH_SHA256};

    usk = new USK(pubKeyHash, cryptoKey, extras, "testsite", 5L);
    fetchContext = newFetchContext();
  }

  private USKFetcherTag newTag(
      USKFetcherCallback callback,
      boolean persistent,
      boolean realTime,
      boolean keepLast,
      boolean checkStoreOnly,
      int token) {
    return USKFetcherTag.create(
        usk,
        callback,
        fetchContext,
        token,
        persistent ? USKFetcherTag.Flag.PERSISTENT : null,
        realTime ? USKFetcherTag.Flag.REAL_TIME : null,
        keepLast ? USKFetcherTag.Flag.KEEP_LAST_DATA : null,
        checkStoreOnly ? USKFetcherTag.Flag.CHECK_STORE_ONLY : null);
  }

  @Test
  @DisplayName("start_nonPersistent_usesOrigUSK_addsCallback_andSchedules")
  void start_nonPersistent_usesOrigUSK_addsCallback_andSchedules() {
    // Arrange
    USKFetcherCallback cb = Mockito.mock(USKFetcherCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 11);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 22);
    USKFetcherTag tag = newTag(cb, false, false, false, false, 42);

    ArgumentCaptor<USK> uskCap = ArgumentCaptor.forClass(USK.class);
    ArgumentCaptor<ClientRequester> reqCap = ArgumentCaptor.forClass(ClientRequester.class);
    when(uskManager.getFetcher(
            uskCap.capture(), eq(fetchContext), reqCap.capture(), eq(false), eq(false)))
        .thenReturn(fetcher);

    // Act
    tag.start(uskManager, mockContext);

    // Assert
    assertSame(
        usk, uskCap.getValue(), "Non-persistent start should pass the original USK instance");
    ClientRequester wrapper = reqCap.getValue();
    assertEquals(
        11, wrapper.getPriorityClass(), "Wrapper priority should match normal polling priority");
    assertFalse(wrapper.realTimeFlag, "Wrapper should not be real-time for realTime=false");
    verify(fetcher, times(1)).addCallback(tag);
    verify(fetcher, times(1)).schedule(mockContext);
  }

  @Test
  @DisplayName("start_persistent_copiesUSK_and_usesRTClient_whenRealTime")
  void start_persistent_copiesUSK_and_usesRTClient_whenRealTime() {
    // Arrange
    USKFetcherCallback cb = Mockito.mock(USKFetcherCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 7);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 9);
    USKFetcherTag tag = newTag(cb, true, true, true, true, 77);

    ArgumentCaptor<USK> uskCap = ArgumentCaptor.forClass(USK.class);
    ArgumentCaptor<ClientRequester> reqCap = ArgumentCaptor.forClass(ClientRequester.class);
    ArgumentCaptor<Boolean> keepLastCap = ArgumentCaptor.forClass(Boolean.class);
    ArgumentCaptor<Boolean> checkStoreOnlyCap = ArgumentCaptor.forClass(Boolean.class);
    when(uskManager.getFetcher(
            uskCap.capture(),
            eq(fetchContext),
            reqCap.capture(),
            keepLastCap.capture(),
            checkStoreOnlyCap.capture()))
        .thenReturn(fetcher);

    // Act
    tag.start(uskManager, mockContext);

    // Assert
    USK used = uskCap.getValue();
    // For persistent=true, USK is copied even if the edition is unchanged
    assertNotSame(used, usk, "Persistent start should pass a copy of the USK");
    assertEquals(used, usk, "Copied USK should be equal to the original");
    ClientRequester wrapper = reqCap.getValue();
    assertTrue(wrapper.realTimeFlag, "Wrapper should be real-time when realTime=true");
    assertEquals(Short.valueOf((short) 7), Short.valueOf(wrapper.getPriorityClass()));
    assertTrue(keepLastCap.getValue(), "keepLastData flag should pass through");
    assertTrue(checkStoreOnlyCap.getValue(), "checkStoreOnly flag should pass through");
    verify(fetcher).addCallback(tag);
    verify(fetcher).schedule(mockContext);
  }

  @Test
  @DisplayName("updatedEdition_higherEdition_passesCopyWithUpdatedEdition")
  void updatedEdition_higherEdition_passesCopyWithUpdatedEdition() {
    // Arrange
    USKFetcherCallback cb = Mockito.mock(USKFetcherCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 5);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 6);
    USKFetcherTag tag = newTag(cb, false, false, false, false, 1);

    long newer = usk.suggestedEdition + 10;
    tag.updatedEdition(newer);

    ArgumentCaptor<USK> uskCap = ArgumentCaptor.forClass(USK.class);
    when(uskManager.getFetcher(
            uskCap.capture(),
            eq(fetchContext),
            any(ClientRequester.class),
            anyBoolean(),
            anyBoolean()))
        .thenReturn(fetcher);

    // Act
    tag.start(uskManager, mockContext);

    // Assert
    USK used = uskCap.getValue();
    assertEquals(
        newer, used.suggestedEdition, "Start must pass a USK copy with the updated edition");
    assertNotSame(used, usk, "USK instance should be a copy when edition increases");
  }

  @Test
  @DisplayName("cancel_invokesFetcherCancel_and_setsFinished")
  void cancel_invokesFetcherCancel_and_setsFinished() {
    // Arrange
    USKFetcherCallback cb = Mockito.mock(USKFetcherCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 1);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 2);
    USKFetcherTag tag = newTag(cb, false, false, false, false, 99);
    when(uskManager.getFetcher(
            any(USK.class),
            any(FetchContext.class),
            any(ClientRequester.class),
            anyBoolean(),
            anyBoolean()))
        .thenReturn(fetcher);
    tag.start(uskManager, mockContext);

    // Act
    tag.cancel(mockContext);

    // Assert
    verify(fetcher, times(1)).cancel(mockContext);
    assertTrue(tag.isFinished(), "Tag should be marked finished after cancel");
  }

  @Test
  @DisplayName("onCancelled_nonPersistent_callsCallbackDirectly_and_setsTagWhenSupported")
  void onCancelled_nonPersistent_callsCallbackDirectly_and_setsTagWhenSupported() {
    // Arrange
    USKFetcherTagCallback cb = Mockito.mock(USKFetcherTagCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 3);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 4);
    USKFetcherTag tag = newTag(cb, false, false, false, false, 10);

    // Act
    tag.onCancelled(mockContext);

    // Assert
    verify(cb, times(1)).setTag(tag, mockContext);
    verify(cb, times(1)).onCancelled(mockContext);
    assertTrue(tag.isFinished(), "Tag should be finished after onCancelled");
  }

  @Test
  @DisplayName("onCancelled_persistent_queuesJobRunner_and_invokesCallbackInsideJob")
  void onCancelled_persistent_queuesJobRunner_and_invokesCallbackInsideJob()
      throws PersistenceDisabledException {
    // Arrange: build a real context with a mocked job runner and manager
    ClientLayerPersister jobRunner = Mockito.mock(ClientLayerPersister.class);
    USKManager manager = Mockito.mock(USKManager.class);
    ClientContext ctx =
        minimalContext(
            jobRunner,
            Mockito.mock(LinkFilterExceptionProvider.class),
            newFetchContext(),
            newInsertContext(),
            manager,
            Mockito.mock(PersistentTempBucketFactory.class),
            Mockito.mock(TempBucketFactory.class));

    USKFetcherTagCallback cb = Mockito.mock(USKFetcherTagCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 8);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 9);
    USKFetcherTag tag = newTag(cb, true, false, false, false, 2);

    // jobRunner.queue should immediately run the job with the provided context
    doAnswer(
            inv -> {
              PersistentJob job = inv.getArgument(0);
              job.run(ctx);
              return null;
            })
        .when(jobRunner)
        .queue(any(PersistentJob.class), anyInt());

    // Act
    tag.onCancelled(ctx);

    // Assert: setTag and onCancelled called via queued job
    verify(cb, times(1)).setTag(tag, ctx);
    verify(cb, times(1)).onCancelled(ctx);
    assertTrue(tag.isFinished(), "Tag should be finished after persistent onCancelled");
  }

  @Test
  @DisplayName("onFailure_afterFinished_doesNotInvokeCallback")
  void onFailure_afterFinished_doesNotInvokeCallback() {
    // Arrange
    USKFetcherCallback cb = Mockito.mock(USKFetcherCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 1);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 2);
    USKFetcherTag tag = newTag(cb, false, false, false, false, 0);
    tag.onCancelled(mockContext); // sets finished

    // Act
    tag.onFailure(mockContext);

    // Assert: no callback, still finished
    verify(cb, times(0)).onFailure(any());
    assertTrue(tag.isFinished());
  }

  @Test
  @DisplayName("onFoundEdition_nonPersistent_invokesCallback_and_setsFinished")
  void onFoundEdition_nonPersistent_invokesCallback_and_setsFinished() {
    // Arrange
    USKFetcherTagCallback cb = Mockito.mock(USKFetcherTagCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 1);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 2);
    USKFetcherTag tag = newTag(cb, false, false, false, false, 123);

    long edition = 42L;
    short codec = 7;
    byte[] data = new byte[] {1, 2, 3};

    // Act
    tag.onFoundEdition(
        new USKFoundEdition(
            new USKFoundEditionPayload(edition, usk.copy(edition), false, codec, data),
            mockContext,
            new USKFoundEditionProgress(true, true)));

    // Assert
    verify(cb, times(1)).setTag(tag, mockContext);
    // Capture and assert arguments instead of eq(...)
    ArgumentCaptor<USKFoundEdition> foundEdition = ArgumentCaptor.forClass(USKFoundEdition.class);
    verify(cb, times(1)).onFoundEdition(foundEdition.capture());
    assertEquals(edition, foundEdition.getValue().edition());
    assertEquals(mockContext, foundEdition.getValue().context());
    assertFalse(foundEdition.getValue().metadata());
    assertEquals(codec, foundEdition.getValue().codec());
    assertArrayEquals(data, foundEdition.getValue().data());
    assertTrue(foundEdition.getValue().newKnownGood());
    assertTrue(foundEdition.getValue().newSlotToo());
    assertTrue(tag.isFinished());

    // Calling again should be ignored because finished
    tag.onFoundEdition(
        new USKFoundEdition(
            new USKFoundEditionPayload(edition + 1, usk.copy(edition + 1), false, codec, data),
            mockContext,
            new USKFoundEditionProgress(true, true)));
    verify(cb, times(1)).onFoundEdition(any(USKFoundEdition.class));
  }

  @Test
  @DisplayName("getters_token_and_priorities")
  void getters_token_and_priorities() {
    USKFetcherCallback cb = Mockito.mock(USKFetcherCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 15);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 25);
    USKFetcherTag tag = newTag(cb, false, false, false, true, 31415);

    assertEquals(31415L, tag.getToken());
    assertEquals(15, tag.getPollingPriorityNormal());
    assertEquals(25, tag.getPollingPriorityProgress());
    assertFalse(tag.isFinished());
  }

  @Test
  @DisplayName("schedule_usesContextUSKManager")
  void schedule_usesContextUSKManager() {
    // Arrange a real-ish context carrying our mocked manager
    ClientLayerPersister jobRunner = Mockito.mock(ClientLayerPersister.class);
    ClientContext ctx =
        minimalContext(
            jobRunner,
            Mockito.mock(LinkFilterExceptionProvider.class),
            newFetchContext(),
            newInsertContext(),
            uskManager,
            Mockito.mock(PersistentTempBucketFactory.class),
            Mockito.mock(TempBucketFactory.class));

    USKFetcherCallback cb = Mockito.mock(USKFetcherCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 5);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 6);
    USKFetcherTag tag = newTag(cb, false, false, false, false, 100);

    when(uskManager.getFetcher(
            any(USK.class),
            eq(fetchContext),
            any(ClientRequester.class),
            anyBoolean(),
            anyBoolean()))
        .thenReturn(fetcher);

    // Act
    tag.schedule(ctx);

    // Assert: start() should have delegated to manager.getFetcher and scheduled the fetcher
    verify(uskManager, times(1))
        .getFetcher(
            any(USK.class),
            eq(fetchContext),
            any(ClientRequester.class),
            anyBoolean(),
            anyBoolean());
    verify(fetcher, times(1)).addCallback(tag);
    verify(fetcher, times(1)).schedule(ctx);
  }

  @Test
  @DisplayName("onResume_whenFinished_doesNothing")
  void onResume_whenFinished_doesNothing() {
    USKFetcherCallback cb = Mockito.mock(USKFetcherCallback.class);
    when(cb.getPollingPriorityNormal()).thenReturn((short) 1);
    when(cb.getPollingPriorityProgress()).thenReturn((short) 2);
    USKFetcherTag tag = newTag(cb, false, false, false, false, 0);
    tag.onCancelled(mockContext); // mark finished

    tag.onResume(mockContext);
    // No interactions expected since finished prevent restart
    verify(uskManager, times(0))
        .getFetcher(
            any(USK.class),
            any(FetchContext.class),
            any(ClientRequester.class),
            anyBoolean(),
            anyBoolean());
  }
}
