package network.crypta.client.async;

import static network.crypta.testsupport.TestRandomData.fillRandomAccessBuffer;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;
import network.crypta.client.ClientMetadata;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import network.crypta.client.async.SplitFileInserterStorage.Status;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.CRCChecksumChecker;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.crypt.MultiHashInputStream;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.node.BaseSendableGet;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableInsert;
import network.crypta.node.SendableRequest;
import network.crypta.node.SendableRequestItem;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.support.CheatingTicker;
import network.crypta.support.DummyJobRunner;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.WaitableExecutor;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.ByteArrayRandomAccessBufferFactory;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.NullOutputStream;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PooledFileRandomAccessBufferFactory;
import network.crypta.support.io.RAFInputStream;
import network.crypta.support.io.ReadOnlyRandomAccessBuffer;
import network.crypta.support.io.TempBucketFactory;
import network.crypta.support.io.TrivialPersistentFileTracker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

// Needed for ClientContext ctor param

@SuppressWarnings("java:S100")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ClientRequestSelectorTest {

  public ClientRequestSelectorTest() throws IOException {
    dir = new File("split-file-inserter-storage-test");
    if (!dir.exists()) {
      // Ensure the test directory exists; assert to fail fast if creation is not possible.
      assertTrue(dir.mkdir(), "Failed to create test directory");
    }
    executor = new WaitableExecutor(new PooledExecutor());
    ticker = new CheatingTicker(executor);
    RandomSource r = new DummyRandomSource(12345);
    fg = new FilenameGenerator(r, true, dir, "freenet-test");
    persistentFileTracker = new TrivialPersistentFileTracker(dir, fg);
    bigRAFFactory = new PooledFileRandomAccessBufferFactory(fg);
    smallBucketFactory = new ArrayBucketFactory();
    bigBucketFactory = new TempBucketFactory(executor, fg, 0, 0, false, 0, null);
    baseContext =
        HighLevelSimpleClientImpl.makeDefaultInsertContext(
            bigBucketFactory, new SimpleEventProducer());
    cryptoKey = new byte[32];
    r.nextBytes(cryptoKey);
    checker = new CRCChecksumChecker();
    memoryLimitedJobRunner =
        new MemoryLimitedJobRunner(
            9 * 1024 * 1024L, 20, executor, NativeThread.JAVA_PRIORITY_RANGE);
    jobRunner = new DummyJobRunner(executor, null);
  }

  @Test
  void splitFileChooseCompletion_whenFailAllThenSucceedAll_expectSucceededStatus()
      throws IOException, InsertException {
    Random r = new Random(12121);
    long size = 65536; // Exact multiple, so no last block
    LockableRandomAccessBuffer data = generateData(r, size, smallRAFFactory);
    HashResult[] hashes = getHashes(data);
    MyCallback cb = new MyCallback();
    InsertContext context = InsertContext.copyOf(baseContext);
    context.maxInsertRetries = 2;
    ClientRequestSelector keys = new ClientRequestSelector(true, false, false, null);
    SplitFileInserterStorage storage =
        new SplitFileInserterStorage(
            data,
            size,
            cb,
            null,
            new ClientMetadata(),
            false,
            null,
            smallRAFFactory,
            false,
            context,
            cryptoAlgorithm,
            cryptoKey,
            null,
            hashes,
            smallBucketFactory,
            checker,
            r,
            memoryLimitedJobRunner,
            jobRunner,
            ticker,
            keys,
            false,
            0,
            0,
            0,
            0);
    storage.start();
    cb.waitForFinishedEncode();
    assertEquals(1, storage.segments.length);
    SplitFileInserterSegmentStorage segment = storage.segments[0];
    assertEquals(2, segment.dataBlockCount);
    assertEquals(3, segment.checkBlockCount);
    assertEquals(0, segment.crossCheckBlockCount);
    assertEquals(Status.ENCODED, storage.getStatus());
    boolean[] chosenBlocks = new boolean[segment.totalBlockCount];
    // Choose and fail all blocks.
    for (int i = 0; i < segment.totalBlockCount; i++) {
      BlockInsert chosen = segment.chooseBlock();
      assertNotNull(chosen);
      keys.addRunningInsert(chosen);
      assertFalse(chosenBlocks[chosen.blockNumber]);
      chosenBlocks[chosen.blockNumber] = true;
      segment.onFailure(
          chosen.blockNumber, new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND));
    }
    BlockInsert chosen = segment.chooseBlock();
    assertNull(chosen);
    for (int i = 0; i < segment.totalBlockCount; i++) {
      keys.removeRunningInsert(new BlockInsert(segment, i));
    }
    // Choose and succeed all blocks.
    chosenBlocks = new boolean[segment.totalBlockCount];
    for (int i = 0; i < segment.totalBlockCount; i++) {
      chosen = segment.chooseBlock();
      keys.addRunningInsert(chosen);
      assertNotNull(chosen);
      assertFalse(chosenBlocks[chosen.blockNumber]);
      chosenBlocks[chosen.blockNumber] = true;
      segment.onInsertedBlock(
          chosen.blockNumber, segment.encodeBlock(chosen.blockNumber).getClientKey());
    }
    cb.waitForSucceededInsert();
    assertEquals(Status.SUCCEEDED, storage.getStatus());
  }

  private HashResult[] getHashes(LockableRandomAccessBuffer data) throws IOException {
    InputStream is = new RAFInputStream(data, 0, data.size());
    MultiHashInputStream hashStream = new MultiHashInputStream(is, HashType.SHA256.bitmask);
    FileUtil.copy(is, new NullOutputStream(), data.size());
    is.close();
    return hashStream.getResults();
  }

  private LockableRandomAccessBuffer generateData(
      Random random, long size, LockableRandomAccessBufferFactory smallRAFFactory)
      throws IOException {
    LockableRandomAccessBuffer thing = smallRAFFactory.makeRAF(size);
    fillRandomAccessBuffer(thing, random, 0, size);
    return new ReadOnlyRandomAccessBuffer(thing);
  }

  private static class MyCallback implements SplitFileInserterStorageCallback {

    @Override
    public synchronized void onFinishedEncode() {
      finishedEncode = true;
      notifyAll();
    }

    @Override
    public synchronized void onHasKeys() {
      notifyAll();
    }

    @Override
    public void encodingProgress() {
      // Ignore.
    }

    public synchronized void waitForFinishedEncode() throws InsertException {
      while (!finishedEncode) {
        checkFailed();
        try {
          wait();
        } catch (InterruptedException e) {
          // Ignore.
        }
      }
    }

    @Override
    public synchronized void onSucceeded(Metadata metadata) {
      succeededInsert = true;
      notifyAll();
    }

    public synchronized void waitForSucceededInsert() throws InsertException {
      while (!succeededInsert) {
        checkFailed();
        try {
          wait();
        } catch (InterruptedException e) {
          // Ignore.
        }
      }
    }

    @Override
    public synchronized void onFailed(InsertException e) {
      failed = e;
      notifyAll();
    }

    @Override
    public void onInsertedBlock() {
      // Ignore.
    }

    @Override
    public void clearCooldown() {
      // Ignore.
    }

    @Override
    public short getPriorityClass() {
      return 0;
    }

    private void checkFailed() throws InsertException {
      if (failed != null) {
        throw failed;
      }
    }

    private boolean finishedEncode;
    private boolean succeededInsert;
    private InsertException failed;
  }

  final LockableRandomAccessBufferFactory smallRAFFactory =
      new ByteArrayRandomAccessBufferFactory();
  final FilenameGenerator fg;
  final PersistentFileTracker persistentFileTracker;
  final LockableRandomAccessBufferFactory bigRAFFactory;
  final BucketFactory smallBucketFactory;
  final BucketFactory bigBucketFactory;
  final File dir;
  final InsertContext baseContext;
  final WaitableExecutor executor;
  final Ticker ticker;
  final byte cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
  final byte[] cryptoKey;
  final ChecksumChecker checker;
  final MemoryLimitedJobRunner memoryLimitedJobRunner;
  final PersistentJobRunner jobRunner;

  // ---------------- Additional unit tests for ClientRequestSelector ----------------

  private ClientContext minimalContext() {
    PriorityAwareExecutor mainExecutor = mock(PriorityAwareExecutor.class);
    Ticker t = mock(Ticker.class);
    ClientLayerPersister runner = mock(ClientLayerPersister.class);
    return new ClientContext(
        1L,
        runner,
        mainExecutor,
        /* archiveManager */ null,
        /* ptbf */ null,
        /* tbf */ null,
        /* tracker */ null,
        /* healingQueue */ null,
        /* uskManager */ null,
        /* strongRandom */ new DummyRandomSource(42),
        /* fastWeakRandom */ new Random(0L),
        /* ticker */ t,
        /* memoryLimitedJobRunner */ null,
        /* fg */ null,
        /* persistentFG */ null,
        /* rafFactory */ null,
        /* persistentRAFFactory */ null,
        /* fileRAFTransient */ null,
        /* fileRAFPersistent */ null,
        /* rc */ null,
        /* checker */ null,
        /* persistentRoot */ null,
        /* cryptoSecretTransient */ null,
        /* linkFilterExceptionProvider */ null,
        /* defaultPersistentFetchContext */ null,
        /* defaultPersistentInsertContext */ null,
        /* config */ null);
  }

  private static byte[] randomNodeChkBytes() {
    byte[] b = new byte[NodeCHK.KEY_LENGTH];
    new Random(1234L).nextBytes(b);
    return b;
  }

  @Test
  void maybeMakeChosenRequest_whenReqNull_returnsNull() {
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(false, false, false, sched);
    assertNull(selector.maybeMakeChosenRequest(null, minimalContext(), System.currentTimeMillis()));
  }

  @Test
  void maybeMakeChosenRequest_whenCancelled_returnsNull() {
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(false, false, false, sched);
    SendableRequest req = mock(SendableRequest.class);
    when(req.isCancelled()).thenReturn(true);
    assertNull(selector.maybeMakeChosenRequest(req, minimalContext(), System.currentTimeMillis()));
  }

  @Test
  void maybeMakeChosenRequest_whenCooldownNonZero_returnsNull() {
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(false, false, false, sched);
    SendableRequest req = mock(SendableRequest.class);
    when(req.isCancelled()).thenReturn(false);
    when(req.getWakeupTime(any(), anyLong())).thenReturn(123L);
    assertNull(selector.maybeMakeChosenRequest(req, minimalContext(), System.currentTimeMillis()));
  }

  @Test
  void maybeMakeChosenRequest_whenChooseKeyNull_returnsNull() {
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(false, false, false, sched);
    SendableRequest req = mock(SendableRequest.class);
    when(req.isCancelled()).thenReturn(false);
    when(req.getWakeupTime(any(), anyLong())).thenReturn(0L);
    when(req.chooseKey(any(), any())).thenReturn(null);
    assertNull(selector.maybeMakeChosenRequest(req, minimalContext(), System.currentTimeMillis()));
  }

  @Test
  void maybeMakeChosenRequest_whenSendableGet_expectChosenBlockWithFlags() {
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(false, false, false, sched);
    ClientContext ctx = minimalContext();

    // Arrange a sendable GET
    SendableGet get = mock(SendableGet.class);
    when(get.isCancelled()).thenReturn(false);
    when(get.getWakeupTime(any(), anyLong())).thenReturn(0L);
    SendableRequestItem token = mock(SendableRequestItem.class);
    when(get.chooseKey(any(), any())).thenReturn(token);

    // Key and client key
    NodeCHK key = new NodeCHK(randomNodeChkBytes(), Key.ALGO_AES_CTR_256_SHA256);
    when(get.getNodeKey(token)).thenReturn(key);
    network.crypta.keys.ClientKey ckey = mock(network.crypta.keys.ClientKey.class);
    when(get.getKey(token)).thenReturn(ckey);

    // FetchContext options
    network.crypta.client.FetchContext fctx =
        HighLevelSimpleClientImpl.makeDefaultFetchContext(
            1024, 1024, null, new SimpleEventProducer());
    fctx.setLocalRequestOnly(true);
    fctx.setIgnoreStore(true);
    fctx.setCanWriteClientCache(true);
    when(get.getContext()).thenReturn(fctx);
    when(get.realTimeFlag()).thenReturn(true);
    when(get.persistent()).thenReturn(false);

    // Act
    ChosenBlock block = selector.maybeMakeChosenRequest(get, ctx, System.currentTimeMillis());

    // Assert
    assertNotNull(block);
    assertSame(token, block.token);
    assertSame(key, block.key);
    assertSame(ckey, block.ckey);
    assertTrue(block.localRequestOnly);
    assertTrue(block.ignoreStore);
    assertTrue(block.canWriteClientCache);
    assertFalse(block.forkOnCacheable); // GET path sets false
    assertTrue(block.realTimeFlag);
    assertFalse(block.isPersistent());
  }

  @Test
  void maybeMakeChosenRequest_whenSendableInsert_expectChosenBlockWithFlags() {
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(true, false, false, sched);
    ClientContext ctx = minimalContext();

    SendableInsert ins = mock(SendableInsert.class);
    when(ins.isCancelled()).thenReturn(false);
    when(ins.getWakeupTime(any(), anyLong())).thenReturn(0L);
    SendableRequestItem token = mock(SendableRequestItem.class);
    when(ins.chooseKey(any(), any())).thenReturn(token);

    // Insert flags
    when(ins.canWriteClientCache()).thenReturn(true);
    when(ins.forkOnCacheable()).thenReturn(true);
    when(ins.localRequestOnly()).thenReturn(true);
    when(ins.realTimeFlag()).thenReturn(false);
    when(ins.persistent()).thenReturn(true);

    ChosenBlock block = selector.maybeMakeChosenRequest(ins, ctx, System.currentTimeMillis());
    assertNotNull(block);
    assertSame(token, block.token);
    assertNull(block.key); // inserts don't expose low-level key here
    assertNull(block.ckey);
    assertTrue(block.localRequestOnly);
    assertFalse(block.ignoreStore); // inserts set ignoreStore=false
    assertTrue(block.canWriteClientCache);
    assertTrue(block.forkOnCacheable);
    assertFalse(block.realTimeFlag);
    assertTrue(block.isPersistent());
  }

  @Test
  void hasKey_whenTrackingAndRemoved_expectGetterWakeupCleared() {
    ClientContext ctx = minimalContext();
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    when(sched.getContext()).thenReturn(ctx);
    ClientRequestSelector selector = new ClientRequestSelector(false, false, false, sched);

    // Key and waiting getter
    NodeCHK key = new NodeCHK(randomNodeChkBytes(), Key.ALGO_AES_CTR_256_SHA256);
    BaseSendableGet getter = mock(BaseSendableGet.class);

    // Not tracked yet → false
    assertFalse(selector.hasKey(key, getter));

    // Start fetching key
    assertTrue(selector.addToFetching(key));

    // Now tracked → true, and getter recorded
    assertTrue(selector.hasKey(key, getter));
    // Duplicate addition is ignored but returns true
    assertTrue(selector.hasKey(key, getter));

    // Removing should clear wakeup time on the waiting getter exactly once
    selector.removeFetchingKey(key);
    verify(getter, times(1)).clearWakeupTime(ctx);
  }

  @Test
  void hasKey_onInsertScheduler_throwsNPE() {
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(true, false, false, sched);
    NodeCHK key = new NodeCHK(randomNodeChkBytes(), Key.ALGO_AES_CTR_256_SHA256);
    assertThrows(
        NullPointerException.class, () -> selector.hasKey(key, mock(BaseSendableGet.class)));
  }

  @Test
  void runningInsert_whenAddThenRemove_expectMembershipChanges() {
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(true, false, false, sched);
    SendableRequestItemKey token = mock(SendableRequestItemKey.class);

    assertTrue(selector.addRunningInsert(token));
    assertTrue(selector.hasInsert(token));
    // Duplicate add → false
    assertFalse(selector.addRunningInsert(token));
    selector.removeRunningInsert(token);
    assertFalse(selector.hasInsert(token));
  }

  @Test
  void addToGrabArray_whenInvalidPriority_expectIllegalState() {
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(false, false, false, sched);
    RequestClient client = mock(RequestClient.class);
    ClientRequestSchedulerGroup group = mock(ClientRequestSchedulerGroup.class);
    SendableRequest req = mock(SendableRequest.class);
    ClientContext ctx = minimalContext();
    assertThrows(
        IllegalStateException.class,
        () -> selector.addToGrabArray((short) -1, client, group, req, ctx));
  }

  @Test
  void chooseRequestInner_whenRegisteredRequestExists_returnsIt() {
    ClientContext ctx = minimalContext();
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(false, false, false, sched);
    RequestClient client = mock(RequestClient.class);
    ClientRequestSchedulerGroup group = mock(ClientRequestSchedulerGroup.class);
    RequestStarter starter = mock(RequestStarter.class);

    SendableGet req = mock(SendableGet.class);
    when(req.getPriorityClass()).thenReturn(RequestStarter.INTERACTIVE_PRIORITY_CLASS);
    when(req.getClient()).thenReturn(client);
    when(req.getSchedulerGroup()).thenReturn(group);
    when(req.getWakeupTime(any(), anyLong())).thenReturn(0L);
    when(req.realTimeFlag()).thenReturn(false);
    when(req.isCancelled()).thenReturn(false);

    // Register
    selector.addToGrabArray(RequestStarter.INTERACTIVE_PRIORITY_CLASS, client, group, req, ctx);

    // Act
    ClientRequestSelector.SelectorReturn ret =
        selector.chooseRequestInner(
            0, new DummyRandomSource(1), null, starter, false, ctx, System.currentTimeMillis());

    // Assert
    assertNotNull(ret);
    assertSame(req, ret.req);
  }

  @Test
  void chooseRequestInner_whenOfferedKeysReadyAndChosen_returnsOfferedKeys() {
    ClientContext ctx = minimalContext();
    ClientRequestScheduler sched = mock(ClientRequestScheduler.class);
    ClientRequestSelector selector = new ClientRequestSelector(false, false, false, sched);

    OfferedKeysList offered = mock(OfferedKeysList.class);
    when(offered.getWakeupTime(any(), anyLong())).thenReturn(0L);
    when(offered.realTimeFlag()).thenReturn(true);

    RandomSource random = mock(RandomSource.class);
    when(random.nextBoolean()).thenReturn(true); // choose offered keys path

    ClientRequestSelector.SelectorReturn ret =
        selector.chooseRequestInner(
            0, random, offered, mock(RequestStarter.class), true, ctx, System.currentTimeMillis());
    assertNotNull(ret);
    assertSame(offered, ret.req);
  }
}
