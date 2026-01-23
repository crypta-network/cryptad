package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import network.crypta.client.ArchiveManager;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.client.filter.LinkFilterExceptionProvider;
import network.crypta.clients.fcp.PersistentRequestRoot;
import network.crypta.config.Config;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.USK;
import network.crypta.node.ClientContextResources;
import network.crypta.node.RequestClient;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.RealCompressor;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.FileRandomAccessBufferFactory;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.InsufficientDiskSpaceException;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentTempBucketFactory;
import network.crypta.support.io.TempBucketFactory;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Allow method names like method_whenCondition_expectOutcome
class USKRetrieverTest {

  private static final String MIME_TEXT_PLAIN = "text/plain";

  // ----------------- Minimal helpers (direct executor/ticker and contexts) -----------------

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
    // Small, deterministic limits; FetchContext is used here only for max{Temp,Output}Length.
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

  private static RequestClient transientClient() {
    return new RequestClient() {
      @Override
      public boolean persistent() {
        return false;
      }

      @Override
      public boolean realTimeFlag() {
        return false;
      }
    };
  }

  private static USK sampleUSK(long edition) throws MalformedURLException {
    byte[] pkHash = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    byte[] cKey = new byte[ClientSSK.CRYPTO_KEY_LENGTH];
    byte[] extra = new byte[5];
    extra[0] = NodeSSK.SSK_VERSION;
    extra[1] = 0; // public (fetch) URI
    extra[2] = Key.ALGO_AES_PCFB_256_SHA256;
    extra[3] = 0; // high byte of HASH_SHA256
    extra[4] = (byte) KeyBlock.HASH_SHA256; // low byte
    return new USK(pkHash, cKey, extra, "mysite", edition);
  }

  // ------------------------------------------- Tests -------------------------------------------

  @Mock private ClientLayerPersister jobRunner;

  @Mock private LinkFilterExceptionProvider linkFilterExceptionProvider;

  @Mock private USKManager uskManager;

  @Mock private PersistentTempBucketFactory ptbf;

  @Mock private TempBucketFactory tbf;

  @Mock private USKRetrieverCallback callback;

  @Test
  void constructor_whenPersistentClient_throwsUnsupportedOperationException() throws Exception {
    FetchContext fctx = newFetchContext();
    USK usk = sampleUSK(5);
    RequestClient persistentClient =
        new RequestClient() {
          @Override
          public boolean persistent() {
            return true;
          }

          @Override
          public boolean realTimeFlag() {
            return false;
          }
        };

    assertThrows(
        UnsupportedOperationException.class,
        () -> new USKRetriever(fctx, (short) 1, persistentClient, callback, usk));
  }

  @Test
  void accessors_returnOriginalUSK_URI_and_isFinishedFalse() throws Exception {
    FetchContext fctx = newFetchContext();
    USK usk = sampleUSK(7);
    USKRetriever retriever = new USKRetriever(fctx, (short) 1, transientClient(), callback, usk);

    assertEquals(usk, retriever.getOriginalUSK());
    assertEquals(usk.getURI(), retriever.getURI());
    // Not a state machine; always returns false
    assertFalse(retriever.isFinished());
  }

  @Test
  void pollingPriority_delegatesToCallback() throws Exception {
    when(callback.getPollingPriorityNormal()).thenReturn((short) 111);
    when(callback.getPollingPriorityProgress()).thenReturn((short) 222);

    USKRetriever retriever =
        new USKRetriever(newFetchContext(), (short) 1, transientClient(), callback, sampleUSK(1));

    assertEquals(111, retriever.getPollingPriorityNormal());
    assertEquals(222, retriever.getPollingPriorityProgress());
  }

  @Test
  void onFailure_withRedirectOrNotEnoughComponents_updatesKnownGood() throws Exception {
    ClientContext ctx =
        minimalContext(
            jobRunner,
            linkFilterExceptionProvider,
            newFetchContext(),
            newInsertContext(),
            uskManager,
            ptbf,
            tbf);
    USK usk = sampleUSK(10);
    USKRetriever retriever =
        new USKRetriever(newFetchContext(), (short) 1, transientClient(), callback, usk);
    ClientGetState state = Mockito.mock(ClientGetState.class);
    when(state.getToken()).thenReturn(42L);

    retriever.onFailure(new FetchException(FetchExceptionMode.PERMANENT_REDIRECT), state, ctx);
    verify(uskManager, times(1)).updateKnownGood(usk, 42L, ctx);

    retriever.onFailure(
        new FetchException(FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS), state, ctx);
    verify(uskManager, times(2)).updateKnownGood(usk, 42L, ctx);
  }

  @Test
  void onFailure_withOtherMode_doesNotUpdateKnownGood() throws Exception {
    ClientContext ctx =
        minimalContext(
            jobRunner,
            linkFilterExceptionProvider,
            newFetchContext(),
            newInsertContext(),
            uskManager,
            ptbf,
            tbf);
    USK usk = sampleUSK(10);
    USKRetriever retriever =
        new USKRetriever(newFetchContext(), (short) 1, transientClient(), callback, usk);
    ClientGetState state = Mockito.mock(ClientGetState.class);
    when(state.getToken()).thenReturn(13L);

    retriever.onFailure(new FetchException(FetchExceptionMode.INTERNAL_ERROR), state, ctx);
    verify(uskManager, never())
        .updateKnownGood(any(USK.class), anyLong(), any(ClientContext.class));
  }

  @Test
  void onSuccess_happyPath_writesToBucket_updatesKnownGood_andNotifiesCallback() throws Exception {
    // Arrange minimal context whose temp bucket factory produces ArrayBucket instances
    when(tbf.makeBucket(anyLong())).thenAnswer(inv -> new ArrayBucket());
    ClientContext ctx =
        minimalContext(
            jobRunner,
            linkFilterExceptionProvider,
            newFetchContext(),
            newInsertContext(),
            uskManager,
            ptbf,
            tbf);

    USK usk = sampleUSK(123);
    USKRetriever retriever =
        new USKRetriever(newFetchContext(), (short) 1, transientClient(), callback, usk);

    ClientGetState state = Mockito.mock(ClientGetState.class);
    when(state.getToken()).thenReturn(77L);

    ClientMetadata meta = new ClientMetadata(MIME_TEXT_PLAIN);
    StreamGenerator generator = Mockito.mock(StreamGenerator.class);
    byte[] payload = "hello-usk".getBytes(StandardCharsets.UTF_8);
    doAnswer(
            inv -> {
              OutputStream os = inv.getArgument(0, OutputStream.class);
              os.write(payload);
              os.flush();
              return null;
            })
        .when(generator)
        .writeTo(any(OutputStream.class), any(ClientContext.class));

    // Act
    retriever.onSuccess(generator, meta, null, state, ctx);

    // Assert: uskManager updated
    verify(uskManager, times(1)).updateKnownGood(usk, 77L, ctx);

    // Assert: callback notified with correct result
    ArgumentCaptor<FetchResult> cap = ArgumentCaptor.forClass(FetchResult.class);
    verify(callback, times(1)).onFound(eq(usk), eq(77L), cap.capture());
    FetchResult res = cap.getValue();
    assertEquals(MIME_TEXT_PLAIN, res.getMetadata().getMIMEType());
    assertEquals(payload.length, res.size());
    try (Bucket b = res.asBucket()) {
      // ArrayBucket exposes the bytes through its API
      assertEquals(payload.length, ((ArrayBucket) b).toByteArray().length);
      assertEquals(new String(payload), new String(((ArrayBucket) b).toByteArray()));
    }
  }

  @Test
  void onSuccess_whenStreamGeneratorThrows_callsOnFailureWithInternalError() throws Exception {
    when(tbf.makeBucket(anyLong())).thenAnswer(inv -> new ArrayBucket());
    ClientContext ctx =
        minimalContext(
            jobRunner,
            linkFilterExceptionProvider,
            newFetchContext(),
            newInsertContext(),
            uskManager,
            ptbf,
            tbf);
    USK usk = sampleUSK(1);
    USKRetriever retriever =
        spy(new USKRetriever(newFetchContext(), (short) 1, transientClient(), callback, usk));
    ClientGetState state = Mockito.mock(ClientGetState.class);
    when(state.getToken()).thenReturn(5L);

    StreamGenerator generator = Mockito.mock(StreamGenerator.class);
    doAnswer(
            inv -> {
              throw new IOException("boom");
            })
        .when(generator)
        .writeTo(any(OutputStream.class), any(ClientContext.class));

    retriever.onSuccess(
        generator, new ClientMetadata("application/octet-stream"), null, state, ctx);

    ArgumentCaptor<FetchException> exc = ArgumentCaptor.forClass(FetchException.class);
    verify(retriever, times(1)).onFailure(exc.capture(), eq(state), eq(ctx));
    assertEquals(FetchExceptionMode.INTERNAL_ERROR, exc.getValue().mode);
  }

  @Test
  void onSuccess_whenMakeBucketThrowsDiskSpace_callsOnFailureWithNotEnoughDiskSpace()
      throws Exception {
    // Arrange BucketFactory to throw InsufficientDiskSpaceException
    when(tbf.makeBucket(anyLong())).thenThrow(new InsufficientDiskSpaceException());
    ClientContext ctx =
        minimalContext(
            jobRunner,
            linkFilterExceptionProvider,
            newFetchContext(),
            newInsertContext(),
            uskManager,
            ptbf,
            tbf);
    USK usk = sampleUSK(2);
    USKRetriever retriever =
        spy(new USKRetriever(newFetchContext(), (short) 1, transientClient(), callback, usk));
    ClientGetState state = Mockito.mock(ClientGetState.class);
    when(state.getToken()).thenReturn(9L);

    retriever.onSuccess(
        Mockito.mock(StreamGenerator.class), new ClientMetadata(MIME_TEXT_PLAIN), null, state, ctx);

    ArgumentCaptor<FetchException> exc = ArgumentCaptor.forClass(FetchException.class);
    verify(retriever, times(1)).onFailure(exc.capture(), eq(state), eq(ctx));
    assertEquals(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE, exc.getValue().mode);
  }

  @Test
  void onSuccess_whenMakeBucketThrowsIOException_callsOnFailureWithBucketError() throws Exception {
    when(tbf.makeBucket(anyLong())).thenThrow(new IOException("io"));
    ClientContext ctx =
        minimalContext(
            jobRunner,
            linkFilterExceptionProvider,
            newFetchContext(),
            newInsertContext(),
            uskManager,
            ptbf,
            tbf);
    USK usk = sampleUSK(3);
    USKRetriever retriever =
        spy(new USKRetriever(newFetchContext(), (short) 1, transientClient(), callback, usk));
    ClientGetState state = Mockito.mock(ClientGetState.class);
    when(state.getToken()).thenReturn(11L);

    retriever.onSuccess(
        Mockito.mock(StreamGenerator.class), new ClientMetadata(MIME_TEXT_PLAIN), null, state, ctx);

    ArgumentCaptor<FetchException> exc = ArgumentCaptor.forClass(FetchException.class);
    verify(retriever, times(1)).onFailure(exc.capture(), eq(state), eq(ctx));
    assertEquals(FetchExceptionMode.BUCKET_ERROR, exc.getValue().mode);
  }

  @Test
  void onFoundEdition_whenNegativeOrLowerThanRequested_noExceptions() throws Exception {
    USK usk = sampleUSK(100);
    USKRetriever retriever =
        new USKRetriever(newFetchContext(), (short) 1, transientClient(), callback, usk);
    ClientContext ctx =
        minimalContext(
            jobRunner,
            linkFilterExceptionProvider,
            newFetchContext(),
            newInsertContext(),
            uskManager,
            ptbf,
            tbf);

    // Negative edition: early return
    assertDoesNotThrow(
        () ->
            retriever.onFoundEdition(
                new USKFoundEdition(-1L, usk, ctx, false, (short) -1, null, false, false)));

    // Lower than requested (origUSK.suggestedEdition == 100): early return
    assertDoesNotThrow(
        () ->
            retriever.onFoundEdition(
                new USKFoundEdition(50L, usk, ctx, false, (short) -1, null, false, false)));
  }

  @Test
  void proxyAndFetcher_accessors_and_unsubscribe_cancelAndUnsubscribe() throws Exception {
    USK usk = sampleUSK(7);
    USKRetriever retriever =
        new USKRetriever(newFetchContext(), (short) 1, transientClient(), callback, usk);
    USKCallback proxy = Mockito.mock(USKCallback.class);
    USKFetcher fetcher = Mockito.mock(USKFetcher.class);

    retriever.setProxy(proxy);
    retriever.setFetcher(fetcher);
    assertEquals(proxy, retriever.getProxy());
    assertEquals(fetcher, retriever.getFetcher());

    // Unsubscribe should cancel fetcher and unsubscribe proxy
    USKManager manager = Mockito.mock(USKManager.class);
    ClientContext ctx =
        minimalContext(
            jobRunner,
            linkFilterExceptionProvider,
            newFetchContext(),
            newInsertContext(),
            uskManager,
            ptbf,
            tbf);
    // USKRetriever.unsubscribe calls manager.getContext(); return our context
    doReturn(ctx).when(manager).getContext();

    retriever.unsubscribe(manager);

    verify(fetcher, times(1)).cancel(ctx);
    verify(manager, times(1)).unsubscribe(usk, proxy);

    // changeUSKPollParameters should delegate when fetcher is set
    retriever.changeUSKPollParameters(30 * 60 * 1000L, 1, ctx);
    // USKRetriever delegates to USKFetcher without passing ClientContext
    verify(fetcher, times(1)).changeUSKPollParameters(30 * 60 * 1000L, 1);
  }

  @Test
  void changeUSKPollParameters_withoutFetcher_throwsIllegalStateException() throws Exception {
    USKRetriever retriever =
        new USKRetriever(newFetchContext(), (short) 1, transientClient(), callback, sampleUSK(1));
    ClientContext ctx =
        minimalContext(
            jobRunner,
            linkFilterExceptionProvider,
            newFetchContext(),
            newInsertContext(),
            uskManager,
            ptbf,
            tbf);

    assertThrows(
        IllegalStateException.class, () -> retriever.changeUSKPollParameters(1000L, 1, ctx));
  }
}
