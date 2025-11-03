package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Random;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.InsertException;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelPutException;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SingleBlockInserterTest {

  private InsertContext insertCtx;

  @Mock private BaseClientPutter parent;
  @Mock private PutCompletionCallback cb;

  private Bucket bucket;

  @BeforeEach
  void setUp() {
    insertCtx =
        new InsertContext(
            /*maxRetries*/ 5,
            /*rnfsToSuccess*/ 2,
            /*splitfileSegmentDataBlocks*/ 1,
            /*splitfileSegmentCheckBlocks*/ 1,
            /*eventProducer*/ new SimpleEventProducer(),
            /*canWriteClientCache*/ true,
            /*forkOnCacheable*/ true,
            /*localRequestOnly*/ false,
            /*compressorDescriptor*/ null,
            /*extraInsertsSingleBlock*/ 0,
            /*extraInsertsSplitfileHeaderBlock*/ 0,
            /*compat*/ CompatibilityMode.COMPAT_CURRENT);
    bucket = mock(Bucket.class);

    // Reasonable parent defaults used by callbacks (lenient to avoid strict stubbing violations)
    Mockito.lenient().when(parent.getPriorityClass()).thenReturn((short) 3);
    Mockito.lenient().when(parent.isCancelled()).thenReturn(false);
  }

  private static ClientContext newMinimalClientContext(InsertContext defaultInsertCtx) {
    // Inline priority-aware executor that runs tasks synchronously
    PriorityAwareExecutor directExec =
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
            return new int[] {0};
          }

          @Override
          public int[] runningThreads() {
            return new int[] {0};
          }

          @Override
          public int getWaitingThreadsCount() {
            return 0;
          }
        };

    MemoryLimitedJobRunner mlr = new MemoryLimitedJobRunner(1, 1, directExec, 1);
    return new ClientContext(
        /*bootID*/ 1L,
        /*jobRunner*/ null,
        /*mainExecutor*/ directExec,
        /*archiveManager*/ null,
        /*ptbf*/ null,
        /*tbf*/ null,
        /*tracker*/ null,
        /*healingQueue*/ null,
        /*uskManager*/ null,
        /*strongRandom*/ new DummyRandomSource(123L),
        /*fastWeakRandom*/ new Random(42L),
        /*ticker*/ new NoopTicker(directExec),
        /*memoryLimitedJobRunner*/ mlr,
        /*fg*/ null,
        /*persistentFG*/ null,
        /*rafFactory*/ null,
        /*persistentRAFFactory*/ null,
        /*fileRAFTransient*/ null,
        /*fileRAFPersistent*/ null,
        /*rc*/ null,
        /*checker*/ null,
        /*persistentRoot*/ null,
        /*cryptoSecretTransient*/ null,
        /*linkFilterExceptionProvider*/ null,
        /*defaultPersistentFetchContext*/ null,
        /*defaultPersistentInsertContext*/ new InsertContext(
            defaultInsertCtx, new SimpleEventProducer()),
        /*config*/ null);
  }

  // --- Tests ---

  @Test
  void constructor_whenAddToParentTrue_notifiesParent() {
    ClientContext ctx = newMinimalClientContext(insertCtx);
    new SingleBlockInserter(
        parent,
        bucket,
        (short) -1,
        FreenetURI.EMPTY_CHK_URI,
        insertCtx,
        /*realTime*/ false,
        cb,
        /*isMetadata*/ false,
        /*sourceLength*/ 0,
        /*token*/ 7,
        /*addToParent*/ true,
        /*dontSendEncoded*/ true,
        /*tokenObject*/ new Object(),
        ctx,
        /*persistent*/ false,
        /*freeData*/ false,
        /*extraInserts*/ 0,
        /*cryptoAlgorithm*/ (byte) 0,
        /*cryptoKey*/ null);

    verify(parent, times(1)).addMustSucceedBlocks(1);
    verify(parent, times(1)).notifyClients(ctx);
  }

  @Test
  void encode_whenDontSendEncodedFalse_callsCallbackAndSetsKey() throws Exception {
    ClientContext ctx = newMinimalClientContext(insertCtx);
    SingleBlockInserter sbi =
        new SingleBlockInserter(
            parent,
            bucket,
            (short) -1,
            FreenetURI.EMPTY_CHK_URI,
            insertCtx,
            false,
            cb,
            false,
            0,
            1,
            false,
            /*dontSendEncoded*/ false,
            new Object(),
            ctx,
            false,
            /*freeData*/ false,
            0,
            (byte) 0,
            null);

    // Spy to stub innerEncode, returning a block with a known key
    SingleBlockInserter spy = Mockito.spy(sbi);
    ClientKeyBlock block = mock(ClientKeyBlock.class);
    ClientKey key = mock(ClientKey.class);
    when(block.getClientKey()).thenReturn(key);
    doReturn(block).when(spy).innerEncode(any(RandomSource.class));

    ClientKeyBlock result = spy.getBlock(ctx);

    assertNotNull(result);
    assertEquals(key, spy.getKeyNoEncode());
    verify(cb, times(1)).onEncode(key, spy, ctx);
  }

  @Test
  void encode_whenDontSendEncodedTrue_doesNotCallCallback() throws Exception {
    ClientContext ctx = newMinimalClientContext(insertCtx);
    SingleBlockInserter sbi =
        new SingleBlockInserter(
            parent,
            bucket,
            (short) -1,
            FreenetURI.EMPTY_CHK_URI,
            insertCtx,
            false,
            cb,
            false,
            0,
            1,
            false,
            /*dontSendEncoded*/ true,
            new Object(),
            ctx,
            false,
            /*freeData*/ false,
            0,
            (byte) 0,
            null);

    SingleBlockInserter spy = Mockito.spy(sbi);
    ClientKeyBlock block = mock(ClientKeyBlock.class);
    ClientKey key = mock(ClientKey.class);
    when(block.getClientKey()).thenReturn(key);
    doReturn(block).when(spy).innerEncode(any(RandomSource.class));

    ClientKeyBlock result = spy.getBlock(ctx);
    assertNotNull(result);
    verify(cb, never()).onEncode(any(), any(), any());
  }

  @Test
  void onFailure_whenCollision_triggersFatalAndFrees() {
    ClientContext ctx = newMinimalClientContext(insertCtx);
    // freeData=true so source bucket is freed on failure
    SingleBlockInserter inserter =
        new SingleBlockInserter(
            parent,
            bucket,
            (short) -1,
            FreenetURI.EMPTY_CHK_URI,
            insertCtx,
            false,
            cb,
            false,
            0,
            1,
            false,
            true,
            new Object(),
            ctx,
            false,
            /*freeData*/ true,
            0,
            (byte) 0,
            null);

    inserter.onFailure(new LowLevelPutException(LowLevelPutException.COLLISION), null, ctx);

    verify(parent, times(1)).fatallyFailedBlock(ctx);
    verify(cb, times(1))
        .onFailure(any(InsertException.class), Mockito.eq(inserter), Mockito.eq(ctx));
    verify(bucket, times(1)).free();
    assertTrue(inserter.isEmpty());
  }

  @Test
  void onFailure_whenRNFThresholdReached_callsOnSuccess() {
    ClientContext ctx = newMinimalClientContext(insertCtx);
    // freeData=true so bucket is freed on success path
    try (ArrayBucket realBucket = new ArrayBucket()) {
      SingleBlockInserter inserter =
          new SingleBlockInserter(
              parent,
              realBucket,
              (short) -1,
              FreenetURI.EMPTY_CHK_URI,
              insertCtx,
              false,
              cb,
              false,
              0,
              1,
              false,
              true,
              new Object(),
              ctx,
              false,
              /*freeData*/ true,
              0,
              (byte) 0,
              null);

      inserter.onFailure(new LowLevelPutException(LowLevelPutException.ROUTE_NOT_FOUND), null, ctx);
      inserter.onFailure(new LowLevelPutException(LowLevelPutException.ROUTE_NOT_FOUND), null, ctx);

      verify(parent, times(1)).completedBlock(false, ctx);
      verify(cb, times(1)).onSuccess(inserter, ctx);
      assertTrue(inserter.isEmpty());
      // ArrayBucket should be freed by inserter; subsequent getInputStream must fail
      assertThrows(IOException.class, realBucket::getInputStream);
    }
  }

  @Test
  void getWakeupTime_whenAlreadyRunningInsert_returnsMax() {
    // Build a mocked context that returns a mocked insert scheduler
    ClientRequestScheduler mockScheduler = mock(ClientRequestScheduler.class);
    KeysFetchingLocally keysFetching = mock(KeysFetchingLocally.class);
    when(mockScheduler.fetchingKeys()).thenReturn(keysFetching);
    when(keysFetching.hasInsert(any())).thenReturn(true);
    ClientContext ctx = mock(ClientContext.class);
    when(ctx.getChkInsertScheduler(false)).thenReturn(mockScheduler);

    SingleBlockInserter inserter =
        new SingleBlockInserter(
            parent,
            bucket,
            (short) -1,
            FreenetURI.EMPTY_CHK_URI,
            insertCtx,
            false,
            cb,
            false,
            0,
            1,
            false,
            true,
            new Object(),
            ctx,
            false,
            false,
            0,
            (byte) 0,
            null);

    long wake = inserter.getWakeupTime(ctx, /*now*/ 0L);
    assertEquals(Long.MAX_VALUE, wake);
  }

  @Test
  void getWakeupTime_whenNotRunning_returnsImmediate() {
    ClientRequestScheduler mockScheduler = mock(ClientRequestScheduler.class);
    KeysFetchingLocally keysFetching = mock(KeysFetchingLocally.class);
    when(mockScheduler.fetchingKeys()).thenReturn(keysFetching);
    when(keysFetching.hasInsert(any())).thenReturn(false);
    ClientContext ctx = mock(ClientContext.class);
    when(ctx.getChkInsertScheduler(false)).thenReturn(mockScheduler);

    SingleBlockInserter inserter =
        new SingleBlockInserter(
            parent,
            bucket,
            (short) -1,
            FreenetURI.EMPTY_CHK_URI,
            insertCtx,
            false,
            cb,
            false,
            0,
            1,
            false,
            true,
            new Object(),
            ctx,
            false,
            false,
            0,
            (byte) 0,
            null);

    long wake = inserter.getWakeupTime(ctx, /*now*/ 0L);
    assertEquals(0L, wake);
  }

  @Test
  void cancel_marksFinished_andNotifies_andFrees() {
    ClientContext ctx = newMinimalClientContext(insertCtx);
    SingleBlockInserter inserter =
        new SingleBlockInserter(
            parent,
            bucket,
            (short) -1,
            FreenetURI.EMPTY_CHK_URI,
            insertCtx,
            false,
            cb,
            false,
            0,
            1,
            false,
            true,
            new Object(),
            ctx,
            false,
            /*freeData*/ true,
            0,
            (byte) 0,
            null);

    inserter.cancel(ctx);

    assertTrue(inserter.isEmpty());
    assertTrue(inserter.isCancelled());
    verify(cb, times(1))
        .onFailure(any(InsertException.class), Mockito.eq(inserter), Mockito.eq(ctx));
    verify(bucket, times(1)).free();
  }

  @Test
  void innerOnResume_callsBucketResume_andCallbackResume_andSchedules() throws Exception {
    ClientContext ctx = newMinimalClientContext(insertCtx);
    SingleBlockInserter sbi =
        new SingleBlockInserter(
            parent,
            bucket,
            (short) -1,
            FreenetURI.EMPTY_CHK_URI,
            insertCtx,
            false,
            cb,
            false,
            0,
            1,
            false,
            true,
            new Object(),
            ctx,
            false,
            false,
            0,
            (byte) 0,
            null);
    SingleBlockInserter spy = Mockito.spy(sbi);
    doNothing().when(spy).schedule(ctx);

    spy.innerOnResume(ctx);

    verify(bucket, times(1)).onResume(ctx);
    verify(cb, times(1)).onResume(ctx);
    verify(spy, times(1)).schedule(ctx);
  }

  @Test
  void flags_and_isSSK_reflectContextAndUri() {
    ClientContext ctx = newMinimalClientContext(insertCtx);
    SingleBlockInserter chkInserter =
        new SingleBlockInserter(
            parent,
            bucket,
            (short) -1,
            FreenetURI.EMPTY_CHK_URI,
            insertCtx,
            false,
            cb,
            true,
            0,
            1,
            false,
            true,
            new Object(),
            ctx,
            false,
            false,
            0,
            (byte) 0,
            null);

    assertFalse(chkInserter.isSSK());
    assertTrue(chkInserter.canWriteClientCache());
    assertTrue(chkInserter.forkOnCacheable());
    assertFalse(chkInserter.localRequestOnly());

    // SSK variant: the constructor only inspects uri.getKeyType()
    SingleBlockInserter sskInserter =
        new SingleBlockInserter(
            parent,
            bucket,
            (short) -1,
            new FreenetURI("SSK", "doc"),
            insertCtx,
            false,
            cb,
            false,
            0,
            1,
            false,
            true,
            new Object(),
            ctx,
            false,
            false,
            0,
            (byte) 0,
            null);
    assertTrue(sskInserter.isSSK());
  }

  @Test
  void innerEncode_static_whenUnknownKeyType_throwsInvalidUri() {
    // Use a USK to trigger the "unknown keytype" path in SingleBlockInserter.innerEncode()
    FreenetURI usk = new FreenetURI("USK", "doc");
    try (ArrayBucket src = new ArrayBucket()) {
      assertThrows(
          InsertException.class,
          () ->
              SingleBlockInserter.innerEncode(
                  new DummyRandomSource(1L),
                  usk,
                  src,
                  /*isMetadata*/ false,
                  (short) -1,
                  /*sourceLength*/ 0,
                  /*compressorDescriptor*/ null,
                  /*cryptoAlgorithm*/ (byte) 0,
                  /*cryptoKey*/ null),
          "Unknown key types must throw InsertException(INVALID_URI)");
    }
  }

  // --- Test helpers ---

  /** No-op ticker used to satisfy ClientContext construction. */
  private static final class NoopTicker implements Ticker {
    private final PriorityAwareExecutor exec;

    NoopTicker(PriorityAwareExecutor exec) {
      this.exec = exec;
    }

    @Override
    public void queueTimedJob(Runnable job, long offset) {
      exec.execute(job);
    }

    @Override
    public void queueTimedJob(
        Runnable job, String name, long offset, boolean runOnTickerAnyway, boolean noDupes) {
      exec.execute(job);
    }

    @Override
    public PriorityAwareExecutor getExecutor() {
      return exec;
    }

    @Override
    public void removeQueuedJob(Runnable job) {
      // no-op
    }

    @Override
    public void queueTimedJobAbsolute(
        Runnable runner, String name, long time, boolean runOnTickerAnyway, boolean noDupes) {
      exec.execute(runner);
    }
  }
}
