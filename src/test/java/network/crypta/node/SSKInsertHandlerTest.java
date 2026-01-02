package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.support.ShortBuffer;
import network.crypta.support.io.NativeThread;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class SSKInsertHandlerTest {

  @Mock Node node;
  @Mock PeerNode source;
  @Mock PeerTransport transport;
  @Mock MessageCore usm;
  @Mock NodeStats nodeStats;
  @Mock InsertTag tag;
  @Mock NodeGetPubkey getPubKey;
  @Mock network.crypta.keys.NodeSSK nodeSSK;

  @Captor ArgumentCaptor<Message> messageCaptor;

  private static SSKInsertHandler newHandler(
      Node node,
      PeerNode source,
      InsertTag tag,
      network.crypta.keys.NodeSSK key,
      byte[] data,
      byte[] headers,
      short htl,
      long uid,
      long startTime,
      boolean canWriteDatastore,
      boolean realTime) {
    // Constructor is package-private; test resides in the same package.
    return new SSKInsertHandler(
        key,
        data,
        headers,
        htl,
        source,
        uid,
        node,
        startTime,
        tag,
        canWriteDatastore,
        /* forkOnCacheable= */ false,
        /* preferInsert= */ true,
        /* ignoreLowBackoff= */ false,
        realTime);
  }

  @BeforeEach
  void setUp() {
    when(node.getUSM()).thenReturn(usm);
    when(node.getNodeStats()).thenReturn(nodeStats);
    when(node.getGetPubKey()).thenReturn(getPubKey);
    when(source.transport()).thenReturn(transport);
    // Minimal required stubbing for constructor path
    when(nodeSSK.getPubKeyHash()).thenReturn(new byte[32]);
  }

  @Test
  @DisplayName("run_whenSendAsyncNotConnected_returnsEarlyAndUnlocks")
  void run_whenSendAsyncNotConnected_returnsEarlyAndUnlocks() throws Exception {
    // Arrange: pubkey not in cache; initial Accepted send throws NotConnected
    when(getPubKey.getKey(any(byte[].class), eq(false), eq(false), eq(null))).thenReturn(null);
    when(transport.sendAsync(any(Message.class), any(), any(ByteCounter.class)))
        .thenThrow(new NotConnectedException());

    long uid = 123L;
    SSKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeSSK,
            /* data= */ null,
            /* headers= */ null,
            (short) 5,
            uid,
            System.currentTimeMillis(),
            /* canWriteDatastore= */ false,
            /* rt= */ false);

    // Act
    handler.run();

    // Assert: attempted Accepted once, then bailed and unlocked; no waits
    verify(transport, times(1)).sendAsync(any(Message.class), any(), eq(handler));
    verify(usm, never()).waitFor(any(MessageFilter.class), any(ByteCounter.class));
    verify(tag, times(1)).unlockHandler();
  }

  @Test
  @DisplayName("run_whenTimeoutWaitingForParts_sendsDataInsertRejected")
  void run_whenTimeoutWaitingForParts_sendsDataInsertRejected() throws Exception {
    // Arrange: pubkey cached so we only need headers/data; waitFor() returns null (timeout)
    when(getPubKey.getKey(any(byte[].class), eq(false), eq(false), eq(null)))
        .thenReturn(org.mockito.Mockito.mock(network.crypta.crypt.DSAPublicKey.class));
    when(usm.waitFor(any(MessageFilter.class), any(ByteCounter.class))).thenReturn(null);

    // Allow sends
    when(transport.sendAsync(any(Message.class), any(), any(ByteCounter.class))).thenReturn(null);
    doNothing().when(transport).sendSync(any(Message.class), any(ByteCounter.class), anyBoolean());

    long uid = 777L;
    SSKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeSSK,
            /* data= */ null,
            /* headers= */ null,
            (short) 4,
            uid,
            System.currentTimeMillis(),
            /* canWriteDatastore= */ true,
            /* rt= */ true);

    // Act
    handler.run();

    // Assert: sends FNPDataInsertRejected with RECEIVE_FAILED
    verify(transport, times(1)).sendSync(messageCaptor.capture(), eq(handler), eq(true));
    Message rejected = messageCaptor.getValue();
    assertEquals(DMT.FNPDataInsertRejected, rejected.getSpec());
    assertEquals(uid, rejected.getLong(DMT.UID));
    assertEquals(
        DMT.DATA_INSERT_REJECTED_RECEIVE_FAILED,
        rejected.getShort(DMT.DATA_INSERT_REJECTED_REASON));
    verify(tag, times(1)).unlockHandler();
  }

  @Test
  @DisplayName("run_whenPubkeyInvalid_sendsRejectedSSKError")
  void run_whenPubkeyInvalid_sendsRejectedSSKError() throws Exception {
    // Arrange: not cached -> need pubkey; waitFor returns a bogus pubkey message that fails to
    // parse
    when(getPubKey.getKey(any(byte[].class), eq(false), eq(false), eq(null))).thenReturn(null);

    long uid = 9911L;
    Message bogusPk = new Message(DMT.FNPSSKPubKey);
    bogusPk.set(DMT.UID, uid);
    bogusPk.set(DMT.PUBKEY_AS_BYTES, new ShortBuffer(new byte[] {1, 2, 3}));
    when(usm.waitFor(any(MessageFilter.class), any(ByteCounter.class))).thenReturn(bogusPk);

    when(transport.sendAsync(any(Message.class), any(), any(ByteCounter.class))).thenReturn(null);
    doNothing().when(transport).sendSync(any(Message.class), any(ByteCounter.class), anyBoolean());

    SSKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeSSK,
            /* data= */ new byte[] {0x01},
            /* headers= */ new byte[] {0x02},
            (short) 2,
            uid,
            System.currentTimeMillis(),
            /* canWriteDatastore= */ true,
            /* rt= */ false);

    // Act
    handler.run();

    // Assert: sendSync with SSK_ERROR rejection
    verify(transport, times(1)).sendSync(messageCaptor.capture(), eq(handler), eq(false));
    Message rej = messageCaptor.getValue();
    assertEquals(DMT.FNPDataInsertRejected, rej.getSpec());
    assertEquals(uid, rej.getLong(DMT.UID));
    assertEquals(DMT.DATA_INSERT_REJECTED_SSK_ERROR, rej.getShort(DMT.DATA_INSERT_REJECTED_REASON));
    verify(tag, times(1)).unlockHandler();
  }

  @Test
  @DisplayName("byteCounters_sentAndReceived_accumulateAndReport")
  void byteCounters_sentAndReceived_accumulateAndReport() {
    SSKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeSSK,
            /* data= */ null,
            /* headers= */ null,
            (short) 1,
            999L,
            System.currentTimeMillis(),
            /* canWriteDatastore= */ true,
            /* rt= */ false);

    handler.sentBytes(120);
    handler.receivedBytes(220);

    assertEquals(120, handler.getTotalSentBytes());
    assertEquals(220, handler.getTotalReceivedBytes());

    verify(nodeStats, times(1)).insertSentBytes(true, 120);
    verify(nodeStats, times(1)).insertReceivedBytes(true, 220);
  }

  @Test
  @DisplayName("sentPayload_reportsNegativeSentBytesAndCallsNode")
  void sentPayload_reportsNegativeSentBytesAndCallsNode() {
    SSKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeSSK,
            /* data= */ null,
            /* headers= */ null,
            (short) 1,
            1001L,
            System.currentTimeMillis(),
            /* canWriteDatastore= */ true,
            /* rt= */ false);

    handler.sentPayload(64);

    verify(node, times(1)).sentPayload(64);
    verify(nodeStats, times(1)).insertSentBytes(true, -64);
  }

  @Test
  @DisplayName("getPriority_returnsHighPriority")
  void getPriority_returnsHighPriority() {
    SSKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeSSK,
            /* data= */ null,
            /* headers= */ null,
            (short) 1,
            1002L,
            System.currentTimeMillis(),
            /* canWriteDatastore= */ true,
            /* rt= */ false);

    assertEquals(NativeThread.PriorityLevel.HIGH_PRIORITY.value, handler.getPriority());
  }

  @Test
  @DisplayName("toString_containsUID")
  void toString_containsUID() {
    long uid = 13579L;
    SSKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeSSK,
            /* data= */ null,
            /* headers= */ null,
            (short) 1,
            uid,
            System.currentTimeMillis(),
            /* canWriteDatastore= */ true,
            /* rt= */ false);
    String s = handler.toString();
    assertTrue(s.contains(" for " + uid));
  }
}
