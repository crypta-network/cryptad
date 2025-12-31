package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKEncodeException;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.math.TimeDecayingRunningAverage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class NodeClientCoreTransfersTest {
  private static final String CHK_SAMPLE = "chk-sample";
  private static final String SSK_DOC_NAME = "test-doc";
  private static final byte[] SSK_SAMPLE_BYTES = "ssk-sample".getBytes(StandardCharsets.UTF_8);

  @Mock private NodeClientCore core;
  @Mock private Node node;
  @Mock private RandomSource random;
  @Mock private RequestStarterGroup requestStarters;
  @Mock private RequestTracker tracker;
  @Mock private RequestCompletionListener completionListener;

  private NodeStats stats;
  private TimeDecayingRunningAverage chkInsertSentAverage;
  private TimeDecayingRunningAverage chkInsertReceivedAverage;
  private TimeDecayingRunningAverage chkInsertSuccessSentAverage;
  private TimeDecayingRunningAverage sskInsertSentAverage;
  private TimeDecayingRunningAverage sskInsertReceivedAverage;
  private TimeDecayingRunningAverage sskInsertSuccessSentAverage;

  private NodeClientCoreTransfers transfers;

  @BeforeEach
  void setUp() throws Exception {
    when(core.getNode()).thenReturn(node);
    when(core.getRandom()).thenReturn(random);
    when(core.getRequestStarters()).thenReturn(requestStarters);
    when(node.getTracker()).thenReturn(tracker);
    when(node.maxHTL()).thenReturn((short) 5);
    lenient().when(random.nextLong()).thenReturn(123L);
    lenient()
        .when(
            tracker.lockUID(
                anyLong(),
                anyBoolean(),
                anyBoolean(),
                anyBoolean(),
                anyBoolean(),
                anyBoolean(),
                any()))
        .thenReturn(true);

    stats = mock(NodeStats.class);
    chkInsertSentAverage = mock(TimeDecayingRunningAverage.class);
    chkInsertReceivedAverage = mock(TimeDecayingRunningAverage.class);
    chkInsertSuccessSentAverage = mock(TimeDecayingRunningAverage.class);
    sskInsertSentAverage = mock(TimeDecayingRunningAverage.class);
    sskInsertReceivedAverage = mock(TimeDecayingRunningAverage.class);
    sskInsertSuccessSentAverage = mock(TimeDecayingRunningAverage.class);

    setField(stats, "localChkFetchBytesSentAverage", mock(TimeDecayingRunningAverage.class));
    setField(stats, "localChkFetchBytesReceivedAverage", mock(TimeDecayingRunningAverage.class));
    setField(
        stats, "successfulChkFetchBytesReceivedAverage", mock(TimeDecayingRunningAverage.class));
    setField(stats, "localSskFetchBytesSentAverage", mock(TimeDecayingRunningAverage.class));
    setField(stats, "localSskFetchBytesReceivedAverage", mock(TimeDecayingRunningAverage.class));
    setField(
        stats, "successfulSskFetchBytesReceivedAverage", mock(TimeDecayingRunningAverage.class));

    setField(stats, "localChkInsertBytesSentAverage", chkInsertSentAverage);
    setField(stats, "localChkInsertBytesReceivedAverage", chkInsertReceivedAverage);
    setField(stats, "successfulChkInsertBytesSentAverage", chkInsertSuccessSentAverage);
    setField(stats, "localSskInsertBytesSentAverage", sskInsertSentAverage);
    setField(stats, "localSskInsertBytesReceivedAverage", sskInsertReceivedAverage);
    setField(stats, "successfulSskInsertBytesSentAverage", sskInsertSuccessSentAverage);

    when(node.getNodeStats()).thenReturn(stats);

    transfers = new NodeClientCoreTransfers(core);
  }

  @Test
  void asyncGet_whenUidLockFails_expectListenerFailedInternalError() {
    Key key = mock(Key.class);
    when(tracker.lockUID(
            anyLong(), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean(), any()))
        .thenReturn(false);

    transfers.asyncGet(key, false, completionListener, true, true, false, false, false);

    ArgumentCaptor<LowLevelGetException> captor =
        ArgumentCaptor.forClass(LowLevelGetException.class);
    verify(completionListener).onFailed(captor.capture());
    assertEquals(LowLevelGetException.INTERNAL_ERROR, captor.getValue().code);
    verify(node, never()).makeRequestSender(any(), anyShort(), anyLong(), any(), any(), any());
  }

  @Test
  void asyncGet_whenKeyBlockInStore_expectListenerSucceeded() {
    Key key = mock(Key.class);
    when(node.makeRequestSender(any(), anyShort(), anyLong(), any(), any(), any()))
        .thenReturn(mock(KeyBlock.class));

    transfers.asyncGet(key, false, completionListener, true, true, false, false, false);

    verify(completionListener).onSucceeded();
    verify(completionListener, never()).onFailed(any());
  }

  @Test
  void asyncGet_whenSenderTimesOut_expectRejectedOverloadAndListenerFailed() {
    Key key = mock(Key.class);
    when(key.toNormalizedDouble()).thenReturn(0.42);
    RequestSender sender = mock(RequestSender.class);
    when(node.makeRequestSender(any(), anyShort(), anyLong(), any(), any(), any()))
        .thenReturn(sender);
    when(sender.getStatus()).thenReturn(RequestSender.TIMED_OUT);
    when(sender.hasForwarded()).thenReturn(false);

    AtomicReference<RequestSenderListener> listenerRef = new AtomicReference<>();
    doAnswer(
            invocation -> {
              listenerRef.set(invocation.getArgument(0));
              return null;
            })
        .when(sender)
        .addListener(any());

    transfers.asyncGet(key, false, completionListener, true, true, true, false, false);

    RequestSenderListener senderListener = listenerRef.get();
    assertNotNull(senderListener);
    senderListener.onRequestSenderFinished(RequestSender.TIMED_OUT, false, sender);

    ArgumentCaptor<LowLevelGetException> captor =
        ArgumentCaptor.forClass(LowLevelGetException.class);
    verify(completionListener).onFailed(captor.capture());
    assertEquals(LowLevelGetException.REJECTED_OVERLOAD, captor.getValue().code);
    verify(requestStarters).rejectedOverload(false, false, true);
    verify(stats).reportCHKOutcome(anyLong(), anyBoolean(), anyDouble(), anyBoolean());
  }

  @Test
  void realGetKey_whenNotChkOrSsk_expectIllegalArgumentException() {
    ClientKey key = mock(ClientKey.class);

    assertThrows(
        IllegalArgumentException.class,
        () -> transfers.realGetKey(key, false, false, false, false));
  }

  @Test
  void realGetKey_whenChkBlockInStore_expectReturnsClientBlock() throws Exception {
    ClientCHKBlock original = encodeSampleChkBlock(CHK_SAMPLE);
    ClientCHK key = original.getClientKey();
    CHKBlock block = original.getBlock();
    when(node.makeRequestSender(any(), anyShort(), anyLong(), any(), any(), any()))
        .thenReturn(block);

    ClientKeyBlock result = transfers.realGetKey(key, true, false, true, false);

    assertEquals(original, result);
  }

  @Test
  void realGetKey_whenSskBlockInStore_expectReturnsClientBlock() throws Exception {
    ClientSSKBlock original = encodeSampleSskBlock(42L);
    ClientSSK key = original.getClientKey();
    SSKBlock block = (SSKBlock) original.getBlock();
    when(node.makeRequestSender(any(), anyShort(), anyLong(), any(), any(), any()))
        .thenReturn(block);

    ClientKeyBlock result = transfers.realGetKey(key, true, false, false, true);

    assertEquals(original, result);
    assertNotNull(key.getPubKey());
  }

  @Test
  void realPut_whenChkBlock_expectDelegatesToRealPutChk() throws Exception {
    NodeClientCoreTransfers spy = spy(transfers);
    CHKBlock block = mock(CHKBlock.class);
    doNothing().when(spy).realPutCHK(block, true, false, true, false, true);

    spy.realPut(block, true, false, true, false, true);

    verify(spy).realPutCHK(block, true, false, true, false, true);
    verify(spy, never())
        .realPutSSK(any(), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean());
  }

  @Test
  void realPut_whenSskBlock_expectDelegatesToRealPutSsk() throws Exception {
    NodeClientCoreTransfers spy = spy(transfers);
    SSKBlock block = mock(SSKBlock.class);
    doNothing().when(spy).realPutSSK(block, true, false, false, false, false);

    spy.realPut(block, true, false, false, false, false);

    verify(spy).realPutSSK(block, true, false, false, false, false);
    verify(spy, never())
        .realPutCHK(any(), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean());
  }

  @Test
  void realPut_whenUnknownBlock_expectIllegalArgumentException() {
    KeyBlock block = mock(KeyBlock.class);

    assertThrows(
        IllegalArgumentException.class,
        () -> transfers.realPut(block, true, false, false, false, false));
  }

  @Test
  void realPutChk_whenSuccessful_expectStoresAndReports() throws Exception {
    ClientCHKBlock clientBlock = encodeSampleChkBlock("chk-put");
    CHKBlock block = clientBlock.getBlock();
    long uid = 456L;
    when(random.nextLong()).thenReturn(uid);

    CHKInsertSender sender = mock(CHKInsertSender.class);
    when(node.makeInsertSender(
            any(), anyShort(), anyLong(), any(), isNull(), any(Node.ChkInsertOptions.class)))
        .thenReturn(sender);
    when(sender.getStatus()).thenReturn(CHKInsertSender.SUCCESS);
    when(sender.sentRequest()).thenReturn(false);
    when(sender.getStatusString()).thenReturn("SUCCESS");
    when(sender.getTotalSentBytes()).thenReturn(123);
    when(sender.getTotalReceivedBytes()).thenReturn(456);
    PeerNode[] routedTo = new PeerNode[0];
    when(sender.getRoutedTo()).thenReturn(routedTo);
    when(sender.completed()).thenReturn(true);
    setField(sender, "uid", uid);

    when(node.shouldStoreDeep(block.getKey(), null, routedTo)).thenReturn(true);
    doNothing().when(node).store(block, true, true, false, false);

    transfers.realPutCHK(block, true, false, false, false, true);

    verify(node).store(block, true, true, false, false);
    verify(chkInsertSentAverage).report(123L);
    verify(chkInsertReceivedAverage).report(456L);
    verify(chkInsertSuccessSentAverage).report(123L);
  }

  @Test
  void realPutChk_whenUidLockFails_expectInternalError() throws Exception {
    ClientCHKBlock clientBlock = encodeSampleChkBlock("chk-fail");
    CHKBlock block = clientBlock.getBlock();
    when(tracker.lockUID(
            anyLong(), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean(), any()))
        .thenReturn(false);

    LowLevelPutException ex =
        assertThrows(
            LowLevelPutException.class,
            () -> transfers.realPutCHK(block, true, false, false, false, false));

    assertEquals(LowLevelPutException.INTERNAL_ERROR, ex.code);
  }

  @Test
  void realPutSsk_whenCollisionInCache_expectLowLevelPutExceptionWithCollidedBlock()
      throws Exception {
    ClientSSKBlock clientBlock = encodeSampleSskBlock(1L);
    SSKBlock block = (SSKBlock) clientBlock.getBlock();
    SSKBlock altBlock = (SSKBlock) encodeSampleSskBlock(2L).getBlock();
    when(node.fetch(block.getKey(), false, true, true, false, false, null)).thenReturn(altBlock);

    LowLevelPutException ex =
        assertThrows(
            LowLevelPutException.class,
            () -> transfers.realPutSSK(block, true, false, false, false, false));

    assertEquals(LowLevelPutException.COLLISION, ex.code);
    assertSame(altBlock, ex.getCollidedBlock());
  }

  @Test
  void realPutSsk_whenSuccessful_expectStoresAndReports() throws Exception {
    ClientSSKBlock clientBlock = encodeSampleSskBlock(7L);
    SSKBlock block = (SSKBlock) clientBlock.getBlock();
    long uid = 789L;
    when(random.nextLong()).thenReturn(uid);
    when(node.fetch(block.getKey(), false, true, true, false, false, null)).thenReturn(null);

    SSKInsertSender sender = mock(SSKInsertSender.class);
    when(node.makeInsertSender(
            any(), anyShort(), anyLong(), any(), isNull(), any(Node.SskInsertOptions.class)))
        .thenReturn(sender);
    when(sender.getStatus()).thenReturn(SSKInsertSender.SUCCESS);
    when(sender.sentRequest()).thenReturn(false);
    when(sender.getStatusString()).thenReturn("SUCCESS");
    when(sender.getTotalSentBytes()).thenReturn(11);
    when(sender.getTotalReceivedBytes()).thenReturn(22);
    PeerNode[] routedTo = new PeerNode[0];
    when(sender.getRoutedTo()).thenReturn(routedTo);
    when(sender.hasCollided()).thenReturn(false);
    setField(sender, "uid", uid);

    when(node.shouldStoreDeep(block.getKey(), null, routedTo)).thenReturn(true);
    doNothing().when(node).storeInsert(block, true, false, true, false);

    transfers.realPutSSK(block, true, false, false, false, false);

    verify(node).storeInsert(block, true, false, true, false);
    verify(sskInsertSentAverage).report(11L);
    verify(sskInsertReceivedAverage).report(22L);
    verify(sskInsertSuccessSentAverage).report(11L);
  }

  @Test
  void queueRandomReinsert_whenCalled_createsAndSchedulesInsert() {
    KeyBlock block = mock(KeyBlock.class);
    AtomicReference<List<?>> ctorArgs = new AtomicReference<>();

    try (MockedConstruction<SimpleSendableInsert> mocked =
        Mockito.mockConstruction(
            SimpleSendableInsert.class, (_, context) -> ctorArgs.set(context.arguments()))) {
      transfers.queueRandomReinsert(block);

      assertEquals(1, mocked.constructed().size());
      List<?> args = ctorArgs.get();
      assertNotNull(args);
      assertSame(core, args.get(0));
      assertSame(block, args.get(1));
      assertEquals(RequestStarter.MAXIMUM_PRIORITY_CLASS, args.get(2));
      verify(mocked.constructed().getFirst()).schedule();
    }
  }

  private ClientCHKBlock encodeSampleChkBlock(String content) throws CHKEncodeException {
    byte[] data = content.getBytes(StandardCharsets.UTF_8);
    return ClientCHKBlock.encode(
        data, false, true, (short) -1, data.length, Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
  }

  private ClientSSKBlock encodeSampleSskBlock(long seed)
      throws SSKEncodeException, IOException, InvalidCompressionCodecException {
    DummyRandomSource rng = new DummyRandomSource(seed);
    InsertableClientSSK key = InsertableClientSSK.createRandom(rng, SSK_DOC_NAME);
    SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(SSK_SAMPLE_BYTES);
    return key.encode(
        bucket, false, true, (short) -1, bucket.size(), Compressor.DEFAULT_COMPRESSORDESCRIPTOR);
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {
    Class<?> type = target.getClass();
    while (type != null) {
      try {
        Field field = type.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
        return;
      } catch (NoSuchFieldException _) {
        type = type.getSuperclass();
      }
    }
    throw new IllegalArgumentException("Field not found: " + fieldName);
  }
}
