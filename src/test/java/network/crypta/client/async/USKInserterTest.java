package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serial;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchContextOptions;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContextOptions;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.USK;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

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
  }

  private record InserterCfg(
      boolean isMetadata,
      boolean addToParent,
      boolean freeData,
      boolean persistent,
      boolean realTimeFlag) {}

  private static final class DummyRandomSource extends RandomSource {
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
    // Minimal ClientContext: only fields touched by these tests are used.
    // Many collaborators are irrelevant here and can be passed as null or simple stubs.
    context =
        new ClientContext(
            1L,
            Mockito.mock(ClientLayerPersister.class),
            new InlineExecutor(),
            null, // ArchiveManager
            null, // PersistentTempBucketFactory
            null, // TempBucketFactory
            null, // PersistentFileTracker
            null, // HealingQueue
            uskManager,
            new DummyRandomSource(),
            new SecureRandom(),
            null, // Ticker
            null, // MemoryLimitedJobRunner
            null, // FilenameGenerator fg
            null, // FilenameGenerator persistentFG
            null, // LockableRandomAccessBufferFactory rafFactory
            null, // LockableRandomAccessBufferFactory persistentRAFFactory
            null, // FileRandomAccessBufferFactory transient
            null, // FileRandomAccessBufferFactory persistent
            null, // RealCompressor
            null, // DatastoreChecker
            null, // PersistentRequestRoot
            null, // MasterSecret transient
            null, // LinkFilterExceptionProvider
            // Default persistent contexts used only when building fetchers internally; not
            // exercised
            // in these tests.
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
            null // Config
            );
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
        parent,
        data,
        compressionCodec,
        uskUri,
        insertCtx,
        cb,
        cfg.isMetadata,
        (int) data.size(),
        123,
        cfg.addToParent,
        "token",
        context,
        cfg.freeData,
        cfg.persistent,
        cfg.realTimeFlag,
        0,
        Key.ALGO_AES_PCFB_256_SHA256,
        null);
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

    // Act: Found matching edition with identical data
    long foundEdition = 7L;
    inserter.onFoundEdition(foundEdition, publicUSK, context, false, (short) 3, bytes, true, true);

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
            parent,
            data,
            (short) 0,
            insertUri,
            ic,
            cb,
            false,
            1,
            7,
            false,
            "tok",
            context,
            false,
            false,
            false,
            0,
            Key.ALGO_AES_PCFB_256_SHA256,
            null);

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

    // Act: first call should notify; second call should be ignored
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

  // Reflection helpers are intentionally omitted; tests use public APIs to prime state.
}
