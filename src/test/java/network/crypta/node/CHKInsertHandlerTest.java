package network.crypta.node;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.keys.NodeCHK;
import network.crypta.support.Ticker;
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

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class CHKInsertHandlerTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  Node node;

  @Mock PeerNode source;
  @Mock PeerTransport transport;
  @Mock MessageCore usm;
  @Mock NodeStats nodeStats;
  @Mock InsertTag tag;
  @Mock Ticker ticker;
  @Mock NodeCHK nodeCHK;

  @Captor ArgumentCaptor<Message> messageCaptor;

  private static CHKInsertHandler newHandler(
      Node node,
      PeerNode source,
      InsertTag tag,
      NodeCHK key,
      short htl,
      long uid,
      long startTime,
      boolean realTime) {
    // Constructor is package-private; the test resides in the same package.
    InsertRoutingOptions options = new InsertRoutingOptions(true, false, false);
    InsertHandlerContext context =
        new InsertHandlerContext(node, source, uid, startTime, tag, options, realTime);
    return new CHKInsertHandler(key, htl, context);
  }

  @BeforeEach
  void setUp() {
    when(node.network().usm()).thenReturn(usm);
    when(node.network().stats()).thenReturn(nodeStats);
    when(node.network().ticker()).thenReturn(ticker);
    when(node.routing().canWriteDatastoreInsert(any(short.class))).thenReturn(true);

    // Source is considered connected for these tests
    when(source.isConnected()).thenReturn(true);
    when(source.timeLastConnectionCompleted()).thenReturn(System.currentTimeMillis());
    when(source.transport()).thenReturn(transport);
  }

  private static long beyondHandshakeWindow() {
    return System.currentTimeMillis() + Node.HANDSHAKE_TIMEOUT * 5L;
  }

  @Test
  @DisplayName("run_whenNoDataInsert_expectTimeoutAndCompletionNotices")
  void run_whenNoDataInsert_expectTimeoutAndCompletionNotices() throws Exception {
    // Arrange: waitFor() returns null to simulate timeout waiting for FNPDataInsert
    when(usm.waitFor(any(MessageFilter.class), any(ByteCounter.class))).thenReturn(null);

    // Peer interactions: allow sending without throwing
    doNothing()
        .when(transport)
        .sendSync(any(Message.class), any(ByteCounter.class), anyBoolean(), anyLong(), anyLong());
    when(transport.sendAsync(any(Message.class), any(), any(ByteCounter.class)))
        .thenAnswer(_ -> null);

    long uid = 42L;
    CHKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeCHK,
            (short) 5,
            uid,
            /* startTime= */ beyondHandshakeWindow(),
            /* realTime= */ false);

    // Act
    handler.run();

    // Assert: 1) First, an FNPAccepted is sent synchronously
    verify(transport, times(1))
        .sendSync(
            messageCaptor.capture(),
            eq(handler),
            eq(false),
            eq(SECONDS.toMillis(15)),
            eq(SECONDS.toMillis(2)));
    Message accepted = messageCaptor.getValue();
    assertEquals(DMT.FNPAccepted, accepted.getSpec(), "Expected FNPAccepted as first send");
    assertEquals(uid, accepted.getLong(DMT.UID));

    // 2) On timeout, a TooSlow (FNPRejectedTimeout) and then InsertTransfersCompleted(true) are
    // sent
    verify(transport, times(1))
        .sendAsync(
            org.mockito.ArgumentMatchers.argThat(
                m ->
                    m != null
                        && m.getSpec().equals(DMT.FNPRejectedTimeout)
                        && m.getLong(DMT.UID) == uid),
            any(),
            eq(handler));

    verify(transport, times(1))
        .sendAsync(
            org.mockito.ArgumentMatchers.argThat(
                m ->
                    m != null
                        && m.getSpec().equals(DMT.FNPInsertTransfersCompleted)
                        && m.getLong(DMT.UID) == uid
                        && m.getBoolean(DMT.ANY_TIMED_OUT)),
            any(),
            eq(handler));

    // 3) The peer is locally marked overloaded (backoff)
    verify(source, times(1)).localRejectedOverload("TimedOutAwaitingDataInsert", false);

    // 4) We register a follow-up async filter for 60s diagnostic window
    verify(usm, times(1)).addAsyncFilter(any(MessageFilter.class), any(), eq(handler));

    // 5) Handler always unlocks the tag in finally
    verify(tag, times(1)).unlockHandler();
  }

  @Test
  @DisplayName("run_whenDataInsertRejected_propagatesRejectionReason")
  void run_whenDataInsertRejected_propagatesRejectionReason() throws Exception {
    // Arrange: the upstream sends FNPDataInsertRejected with a reason
    long uid = 777L;
    short reason = DMT.DATA_INSERT_REJECTED_RECEIVE_FAILED;
    Message rejected = DMT.createFNPDataInsertRejected(uid, reason);

    when(usm.waitFor(any(MessageFilter.class), any(ByteCounter.class))).thenReturn(rejected);

    doNothing()
        .when(transport)
        .sendSync(any(Message.class), any(ByteCounter.class), anyBoolean(), anyLong(), anyLong());
    when(transport.sendAsync(any(Message.class), any(), any(ByteCounter.class)))
        .thenAnswer(_ -> null);

    CHKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeCHK,
            (short) 3,
            uid,
            /* startTime= */ beyondHandshakeWindow(),
            /* realTime= */ true);

    // Act
    handler.run();

    // Assert: first, FNPAccepted; then echo FNPDataInsertRejected with the same reason
    verify(transport, times(1))
        .sendSync(
            any(Message.class),
            eq(handler),
            eq(true),
            eq(SECONDS.toMillis(15)),
            eq(SECONDS.toMillis(2)));

    verify(transport, times(1)).sendAsync(messageCaptor.capture(), any(), eq(handler));
    Message echoed = messageCaptor.getValue();
    assertEquals(DMT.FNPDataInsertRejected, echoed.getSpec());
    assertEquals(uid, echoed.getLong(DMT.UID));
    assertEquals(reason, echoed.getShort(DMT.DATA_INSERT_REJECTED_REASON));

    verify(tag, times(1)).unlockHandler();
  }

  @Test
  @DisplayName("byteCounters_sentAndReceived_accumulateAndReport")
  void byteCounters_sentAndReceived_accumulateAndReport() {
    CHKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeCHK,
            (short) 1,
            999L,
            /* startTime= */ beyondHandshakeWindow(),
            /* realTime= */ false);

    handler.sentBytes(100);
    handler.receivedBytes(250);

    assertEquals(100, handler.getTotalSentBytes());
    assertEquals(250, handler.getTotalReceivedBytes());

    verify(nodeStats, times(1)).insertSentBytes(false, 100);
    verify(nodeStats, times(1)).insertReceivedBytes(false, 250);
  }

  @Test
  @DisplayName("sentPayload_reportsNegativeSentBytesAndCallsNode")
  void sentPayload_reportsNegativeSentBytesAndCallsNode() {
    CHKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeCHK,
            (short) 1,
            1001L,
            /* startTime= */ beyondHandshakeWindow(),
            /* realTime= */ false);

    handler.sentPayload(64);

    verify(node, times(1)).sentPayload(64);
    verify(nodeStats, times(1)).insertSentBytes(false, -64);
  }

  @Test
  @DisplayName("getPriority_returnsHighPriority")
  void getPriority_returnsHighPriority() {
    CHKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeCHK,
            (short) 1,
            1002L,
            /* startTime= */ beyondHandshakeWindow(),
            /* realTime= */ false);

    assertEquals(NativeThread.PriorityLevel.HIGH_PRIORITY.value, handler.getPriority());
  }

  @Test
  @DisplayName("toString_containsUID")
  void toString_containsUID() {
    long uid = 13579L;
    CHKInsertHandler handler =
        newHandler(
            node,
            source,
            tag,
            nodeCHK,
            (short) 1,
            uid,
            /* startTime= */ beyondHandshakeWindow(),
            /* realTime= */ false);
    String s = handler.toString();
    assertTrue(s.contains(" for " + uid));
  }
}
